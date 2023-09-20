// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"

	"github.com/volcengine/cello/pkg/utils/logger"
	utilruntime "github.com/volcengine/cello/pkg/utils/runtime"
	"github.com/volcengine/cello/types"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "k8s"})

type Service interface {
	// ListLocalPods list local pod from api server
	ListLocalPods(ctx context.Context) ([]*corev1.Pod, error)

	// GetPod get pod from api server
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)

	// ListCachedPods list local pod from local cached(informer)
	ListCachedPods() ([]*corev1.Pod, error)

	// ListCachedPodsWithLabelSelector list local pod with selector from local cached(informer)
	ListCachedPodsWithLabelSelector(selector labels.Selector) ([]*corev1.Pod, error)

	// GetCachedPod get local pod from local cached(informer)
	GetCachedPod(namespace, name string) (*corev1.Pod, error)

	// GetLocalNode get the node itself from api server
	GetLocalNode(ctx context.Context) (*corev1.Node, error)

	// GetConfigMap get configmap from api server
	GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)

	// GetNodeDynamicConfigName get namespace and name of dynamic configmap that separated by '.'
	GetNodeDynamicConfigName() string

	// RecordNodeEvent record events of node
	RecordNodeEvent(eventType, reason, message string)

	// RecordPodEvent record events of pod
	RecordPodEvent(podName, podNamespace, eventType, reason, message string) error

	// EvictPod evict the specific pod
	EvictPod(ctx context.Context, podName, namespace string) error

	// AddConfigMapEventHandler add handler which called while configmap cello-config changed
	AddConfigMapEventHandler(handler cache.ResourceEventHandlerFuncs)

	// PatchTrunkInfo patch trunk info to node annotation
	PatchTrunkInfo(info *types.TrunkInfo) error

	// PatchPodAnnotation patch annotation to pod
	PatchPodAnnotation(ctx context.Context, namespace, name string, anno map[string]string) error
}

type k8sManager struct {
	nodeName      string
	node          *corev1.Node
	rawKubeClient kubernetes.Interface
	broadcaster   record.EventBroadcaster
	recorder      record.EventRecorder

	podListerOnce     sync.Once
	podListerReady    chan struct{} // podListerReady close means podLister is ready
	podLister         listers.PodLister
	configMapInformer cache.SharedIndexInformer
}

func (k *k8sManager) ListLocalPods(ctx context.Context) ([]*corev1.Pod, error) {
	options := metav1.ListOptions{
		ResourceVersion: "0",
	}
	options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", k.nodeName).String()

	list, err := k.rawKubeClient.CoreV1().Pods(corev1.NamespaceAll).List(ctx, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed listting pods on %s from apiserver", k.nodeName)
	}
	var podList []*corev1.Pod
	for i := range list.Items {
		pod := list.Items[i]
		if pod.Spec.HostNetwork == true {
			continue
		}
		podList = append(podList, &pod)
	}

	return podList, nil
}

// GetPod by namespace + name.
func (k *k8sManager) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return k.rawKubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{ResourceVersion: "0"})
}

func (k *k8sManager) GetLocalNode(ctx context.Context) (*corev1.Node, error) {
	return k.rawKubeClient.CoreV1().Nodes().Get(ctx, k.nodeName, metav1.GetOptions{ResourceVersion: "0"})
}

func (k *k8sManager) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return k.rawKubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{ResourceVersion: "0"})
}

func (k *k8sManager) GetNodeDynamicConfigName() string {
	node, err := k.GetLocalNode(context.TODO())
	if err != nil {
		return ""
	}
	cfName, exist := node.Labels[types.LabelNodeDynamicConfigKey]
	if !exist {
		return ""
	}
	return cfName
}

func (k *k8sManager) RecordNodeEvent(eventType, reason, message string) {
	ref := &corev1.ObjectReference{
		Kind:      "Node",
		Name:      k.node.Name,
		UID:       k.node.UID,
		Namespace: "",
	}

	k.recorder.Event(ref, eventType, reason, message)
}

func (k *k8sManager) RecordPodEvent(podName, podNamespace, eventType, reason, message string) error {
	pod, err := k.rawKubeClient.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metav1.GetOptions{
		ResourceVersion: "0",
	})

	if err != nil {
		return err
	}

	ref := &corev1.ObjectReference{
		Kind:      "Pod",
		Name:      pod.Name,
		UID:       pod.UID,
		Namespace: pod.Namespace,
	}

	k.recorder.Event(ref, eventType, reason, message)
	return nil
}

func (k *k8sManager) initPodInformer() {
	setupSignalHandler := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			defer utilruntime.HandleCrash(log)
			<-c
			cancel()
			<-c
			os.Exit(1) // second signal. Exit directly.
		}()
		return ctx
	}

	stopCh := setupSignalHandler()
	// create shared Informer Factory
	factory := informers.NewSharedInformerFactoryWithOptions(k.rawKubeClient, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.Kind = "Pod"
			options.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + k.nodeName).String()
		}))
	// add pod informer only
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	defer runtime.HandleCrash()

	// start pod informer
	go factory.Start(stopCh.Done()) //FIXME: No Need to start a goroutine, start() will create a new one.
	// wait informer synced
	if !cache.WaitForCacheSync(stopCh.Done(), informer.HasSynced) {
		log.Errorf("Timeout to wait pod informer synced")
		runtime.HandleError(fmt.Errorf("wait pod informer synced failed, timeout"))
		return
	}
	k.podLister = podInformer.Lister()
	// mark podLister ready
	k.podListerOnce.Do(func() {
		close(k.podListerReady)
		log.Infof("K8s pod informer synced, pod lister ready")
	})
}

func (k *k8sManager) initConfigMapInformer() {
	setupSignalHandler := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			defer utilruntime.HandleCrash(log)
			<-c
			cancel()
			<-c
			os.Exit(1) // second signal. Exit directly.
		}()
		return ctx
	}

	stopCh := setupSignalHandler()
	// Create shared Informer Factory for cluster ConfigMap.
	informersFactory := informers.NewSharedInformerFactoryWithOptions(k.rawKubeClient, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.Kind = "ConfigMap"
			options.FieldSelector = fields.ParseSelectorOrDie(
				"metadata.name=cello-config,metadata.namespace=kube-system").String()
		}))
	// Add configmap informer.
	k.configMapInformer = informersFactory.Core().V1().ConfigMaps().Informer()
	informersFactory.Start(stopCh.Done())
	// wait informer synced
	if !cache.WaitForCacheSync(stopCh.Done(), k.configMapInformer.HasSynced) {
		log.Errorf("Timeout to wait configmap informer synced")
		runtime.HandleError(fmt.Errorf("wait configmap informer synced failed, timeout"))
		return
	}
}

func (k *k8sManager) ListCachedPods() ([]*corev1.Pod, error) {
	return k.ListCachedPodsWithLabelSelector(labels.Everything())
}

func (k *k8sManager) ListCachedPodsWithLabelSelector(selector labels.Selector) ([]*corev1.Pod, error) {
	<-k.podListerReady
	return k.podLister.Pods(corev1.NamespaceAll).List(selector)
}

func (k *k8sManager) GetCachedPod(namespace, name string) (*corev1.Pod, error) {
	<-k.podListerReady
	ns := corev1.NamespaceAll
	if namespace != "" {
		ns = namespace
	}
	return k.podLister.Pods(ns).Get(name)
}

// PatchTrunkInfo
// if annotation value is empty, we will remove it or set it
// k8s.volcengine.com/trunk-eni: {"eniID":"xxx"}.
func (k *k8sManager) PatchTrunkInfo(info *types.TrunkInfo) error {
	node, err := k.rawKubeClient.CoreV1().Nodes().Get(context.TODO(), k.nodeName, metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return err
	}

	var currentInfo *types.TrunkInfo
	currentInfoAbnormal := false
	if node.GetAnnotations() != nil {
		if oldInfoStr, ok := node.GetAnnotations()[types.AnnotationTrunkENI]; ok {
			var oldInfo types.TrunkInfo
			err = json.Unmarshal([]byte(oldInfoStr), &oldInfo)
			if err != nil {
				// "" or broken json struct
				currentInfoAbnormal = true
			} else {
				currentInfo = &oldInfo
			}
		}
	}
	if !currentInfoAbnormal && reflect.DeepEqual(info, currentInfo) {
		// current info is expected, skip
		return nil
	}

	// trunk info changed, default is nil let apiserver remove annotation key
	var infoValue interface{}
	if info != nil {
		b, err := json.Marshal(info)
		if err != nil {
			return err
		}
		infoValue = string(b)
	}
	annotation := map[string]map[string]map[string]interface{}{
		"metadata": {
			"annotations": {
				types.AnnotationTrunkENI: infoValue,
			},
		},
	}
	annotationPatchStr, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	_, err = k.rawKubeClient.CoreV1().Nodes().Patch(context.TODO(), k.nodeName, k8sTypes.MergePatchType, []byte(annotationPatchStr), metav1.PatchOptions{})
	return err
}

func (k *k8sManager) PatchPodAnnotation(ctx context.Context, namespace, name string, anno map[string]string) error {
	log.Infof("show ns:%s, name:%s, PodAnnotation:%v", namespace, name, anno)
	return retry.OnError(retry.DefaultBackoff, func(err error) bool {
		return true
	}, func() error {
		patch := map[string]map[string]map[string]string{
			"metadata": {
				"annotations": anno,
			},
		}
		patchData, _ := json.Marshal(patch)
		_, err := k.rawKubeClient.CoreV1().Pods(namespace).Patch(ctx, name, k8sTypes.StrategicMergePatchType, patchData, metav1.PatchOptions{})
		return err
	})
}

func NewK8sService(nodeName string, clientSet kubernetes.Interface) (Service, error) {
	node, err := clientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		return nil, fmt.Errorf("failed get node failed, %s", err.Error())
	}

	broadcaster := record.NewBroadcaster()
	source := corev1.EventSource{Component: "cello-daemon"}
	recorder := broadcaster.NewRecorder(scheme.Scheme, source)

	sink := &typedv1.EventSinkImpl{
		Interface: typedv1.New(clientSet.CoreV1().RESTClient()).Events(""),
	}
	broadcaster.StartRecordingToSink(sink)

	k8sM := &k8sManager{
		nodeName:       nodeName,
		rawKubeClient:  clientSet,
		broadcaster:    broadcaster,
		recorder:       recorder,
		node:           node,
		podListerReady: make(chan struct{}),
	}
	log.Infof("Init pod informer...")
	go k8sM.initPodInformer()
	k8sM.initConfigMapInformer()
	return k8sM, nil
}

func (k *k8sManager) EvictPod(ctx context.Context, podName, namespace string) error {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	}
	return k.rawKubeClient.PolicyV1beta1().Evictions(namespace).Evict(context.Background(), eviction)
}

func (k *k8sManager) AddConfigMapEventHandler(handler cache.ResourceEventHandlerFuncs) {
	k.configMapInformer.AddEventHandler(handler)
}
