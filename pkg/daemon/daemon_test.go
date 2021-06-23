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

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	goipam "github.com/metal-stack/go-ipam"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"

	"github.com/volcengine/cello/pkg/config"
	"github.com/volcengine/cello/pkg/deviceplugin"
	"github.com/volcengine/cello/pkg/k8s"
	"github.com/volcengine/cello/pkg/pbrpc"
	helper "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper"
	apiErr "github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/errors"
	"github.com/volcengine/cello/pkg/provider/volcengine/cellohelper/mock"
	"github.com/volcengine/cello/pkg/provider/volcengine/ec2"
	ec2Mock "github.com/volcengine/cello/pkg/provider/volcengine/ec2/mock"
	"github.com/volcengine/cello/pkg/utils/datatype"
	"github.com/volcengine/cello/types"
)

const (
	eniIdPrefix     = "eni-fake"
	secGrpIdPrefix  = "sg-fake"
	subnetIdPrefix  = "subnet-fake"
	requestIdPrefix = "request-fake"
)

func GenerateEniId() string {
	temp := uuid.NewUUID()
	return fmt.Sprintf("%s%s", eniIdPrefix, temp[:21])
}

func GenerateSecurityGroupId() string {
	temp := uuid.NewUUID()
	return fmt.Sprintf("%s%s", secGrpIdPrefix, temp[:21])
}

func GenerateSubnetId() string {
	temp := uuid.NewUUID()
	return fmt.Sprintf("%s%s", subnetIdPrefix, temp[:21])
}

func GenerateMac() net.HardwareAddr {
	var mac [6]byte
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 6; i++ {
		bV := rand.Intn(256)
		mac[i] = byte(bV)
		rand.Seed(int64(bV))
	}
	return mac[:]
}

func GenerateRequestId() string {
	temp := uuid.NewUUID()
	return fmt.Sprintf("%s%s", requestIdPrefix, temp[:21])
}

type ENIKeeper struct {
	types.ENI
	ipv4s        sync.Map
	ipv6s        sync.Map
	isPrimary    bool
	celloCreated bool
	ipv4Tickets  chan struct{}
	ipv6Tickets  chan struct{}
}

func (e *ENIKeeper) putIPv4(ip *goipam.IP) error {
	if ip == nil {
		return nil
	}
	select {
	case e.ipv4Tickets <- struct{}{}:
		e.ipv4s.Store(ip.IP.String(), ip)
	default:
		return errors.New(apiErr.LimitExceededPrivateIpsPerEni)
	}
	return nil
}

func (e *ENIKeeper) removeIPv4(ip *goipam.IP) error {
	if ip == nil {
		return nil
	}
	if _, exist := e.ipv4s.Load(ip.IP.String()); exist {
		e.ipv4s.Delete(ip.IP.String())
		select {
		case <-e.ipv4Tickets:
		default:
		}
	} else {
		return errors.New(fmt.Sprintf("%s, %s", apiErr.InvalidPrivateIpMalformed, ip.IP.String()))
	}
	return nil
}

func (e *ENIKeeper) putIPv6(ip *goipam.IP) error {
	if ip == nil {
		return nil
	}
	select {
	case e.ipv6Tickets <- struct{}{}:
		e.ipv6s.Store(ip.IP.String(), ip)
	default:
		return errors.New(apiErr.LimitExceededPrivateIpsPerEni)
	}
	return nil
}

func (e *ENIKeeper) removeIPv6(ip *goipam.IP) error {
	if ip == nil {
		return nil
	}
	if _, exist := e.ipv6s.Load(ip.IP.String()); exist {
		e.ipv6s.Delete(ip.IP.String())
		select {
		case <-e.ipv6Tickets:
		default:
		}
	} else {
		return errors.New(fmt.Sprintf("%s, %s", apiErr.InvalidIpv6Malformed, ip.IP.String()))
	}
	return nil
}

type APIMockDB struct {
	ipFamily types.IPFamily
	helper.InstanceLimits
	eniCache   sync.Map
	eniTickets chan struct{}
	subnets    map[string]*types.Subnet
	ipam       goipam.Ipamer
	prefixes   map[string]*goipam.Prefix

	readOnlyRateLimiter flowcontrol.RateLimiter
	writeRateLimiter    flowcontrol.RateLimiter
}

func (v *APIMockDB) putENI(eni *ENIKeeper) error {
	if eni == nil {
		return nil
	}
	select {
	case v.eniTickets <- struct{}{}:
		v.eniCache.Store(eni.ID, eni)
	default:
		return errors.New(apiErr.LimitExceededEnisPerInstance)
	}
	return nil
}

func (v *APIMockDB) removeENI(eni *ENIKeeper) error {
	if eni == nil {
		return nil
	}
	if _, exist := v.eniCache.Load(eni.ID); exist {
		v.eniCache.Delete(eni.ID)
		select {
		case <-v.eniTickets:
		default:
		}
	} else {
		return errors.New(apiErr.InvalidEniIdNotFound)
	}
	return nil
}

func (v *APIMockDB) acquireIP(cidr string) (*goipam.IP, error) {
	prefix, ok := v.prefixes[cidr]
	if !ok {
		return nil, errors.New(apiErr.InvalidSubnetNotFound)
	}
	ip, inErr := v.ipam.AcquireIP(context.Background(), prefix.String())
	if inErr != nil {
		if errors.Is(inErr, goipam.ErrNoIPAvailable) {
			return nil, errors.New(apiErr.InsufficientIpInSubnet)
		}
		if errors.Is(inErr, goipam.ErrAlreadyAllocated) {
			return nil, errors.New(apiErr.InvalidPrivateIpMalformed)
		}
		return nil, fmt.Errorf("%s, %v", apiErr.InternalError, inErr)
	}
	return ip, nil
}

func (v *APIMockDB) AllocENI(subnetId string, securityGroups []string, trunk bool, ipCnt int) (res *types.ENI, err error) {
	subnet, exist := v.subnets[subnetId]
	if !exist {
		return nil, errors.New(apiErr.InvalidSubnetNotFound)
	}
	return v.createENI(subnet, securityGroups, trunk, false, true, ipCnt)
}

func (v *APIMockDB) createENI(subnet *types.Subnet, securityGroups []string, trunk, primary, celloCreated bool, ipCnt int) (res *types.ENI, err error) {
	if !v.writeRateLimiter.TryAccept() {
		return nil, errors.New(apiErr.AccountFlowLimitExceeded)
	}
	if (v.ipFamily.EnableIPv4() && subnet.CIDR.IPv4 == nil) ||
		(v.ipFamily.EnableIPv6() && subnet.CIDR.IPv6 == nil) {
		return nil, fmt.Errorf("subnet %s has no ipv4 cidr or ipv6 cidr while ipFamily is %s", subnet.ID, v.ipFamily)
	}

	if ipCnt < 1 {
		return nil, fmt.Errorf("invalid ip cnt")
	}

	ipv4Cnt, ipv6Cnt := ipCnt, ipCnt
	if !v.ipFamily.EnableIPv4() {
		ipv4Cnt = 0
	}
	if !v.ipFamily.EnableIPv6() {
		ipv6Cnt = 0
	}

	eni := &ENIKeeper{
		ENI: types.ENI{
			ID:               GenerateEniId(),
			Mac:              GenerateMac(),
			PrimaryIP:        types.IPSet{},
			Subnet:           *subnet,
			SecurityGroupIDs: securityGroups,
			Trunk:            trunk,
		},
		celloCreated: celloCreated,
		ipv4s:        sync.Map{},
		ipv6s:        sync.Map{},
		ipv4Tickets:  make(chan struct{}, v.IPv4MaxPerENI),
		ipv6Tickets:  make(chan struct{}, v.IPv6MaxPerENI),
	}

	defer func() {
		if err != nil {
			eni.ipv4s.Range(func(key, value any) bool {
				_, _ = v.ipam.ReleaseIP(context.Background(), value.(*goipam.IP))
				return true
			})

			eni.ipv6s.Range(func(key, value any) bool {
				_, _ = v.ipam.ReleaseIP(context.Background(), value.(*goipam.IP))
				return true
			})
		}
	}()

	if v.ipFamily.EnableIPv4() {
		ipv4Cnt = ipCnt - 1
		ip, inErr := v.acquireIP(subnet.CIDR.IPv4.String())
		if inErr != nil {
			return nil, inErr
		}
		eni.PrimaryIP.IPv4 = net.ParseIP(ip.IP.String())
		if inErr = eni.putIPv4(ip); inErr != nil {
			return nil, inErr
		}
	}

	if eni.PrimaryIP.IPv4 == nil && v.ipFamily.EnableIPv6() {
		ipv6Cnt = ipCnt - 1
		ip, inErr := v.acquireIP(subnet.CIDR.IPv6.String())
		if inErr != nil {
			return nil, inErr
		}
		eni.PrimaryIP.IPv6 = net.ParseIP(ip.IP.String())
		if inErr = eni.putIPv6(ip); inErr != nil {
			return nil, inErr
		}
	}

	if primary {
		ipv4Cnt = 0
		ipv6Cnt = 0
		eni.isPrimary = primary
		eni.celloCreated = false
		eni.Trunk = false
	}

	for i := 0; i < ipv4Cnt; i++ {
		ip, inErr := v.acquireIP(subnet.CIDR.IPv4.String())
		if inErr != nil {
			return nil, inErr
		}
		if inErr = eni.putIPv4(ip); inErr != nil {
			return nil, inErr
		}
	}

	for i := 0; i < ipv6Cnt; i++ {
		ip, inErr := v.acquireIP(subnet.CIDR.IPv6.String())
		if inErr != nil {
			return nil, inErr
		}
		if inErr = eni.putIPv6(ip); inErr != nil {
			return nil, inErr
		}
	}

	if err = v.putENI(eni); err != nil {
		return nil, err
	}

	return &eni.ENI, nil
}

func (v *APIMockDB) FreeENI(eniID string) error {
	if !v.writeRateLimiter.TryAccept() {
		return errors.New(apiErr.AccountFlowLimitExceeded)
	}
	if poolEni, exist := v.eniCache.Load(eniID); exist {
		eni := poolEni.(*ENIKeeper)
		if eni.isPrimary {
			return errors.New(apiErr.InvalidEniInvalidStatus)
		}
		eni.ipv4s.Range(func(key, value any) bool {
			_, _ = v.ipam.ReleaseIP(context.Background(), value.(*goipam.IP))
			return true
		})
		eni.ipv6s.Range(func(key, value any) bool {
			_, _ = v.ipam.ReleaseIP(context.Background(), value.(*goipam.IP))
			return true
		})
		return v.removeENI(eni)
	} else {
		return errors.New(apiErr.InvalidEniIdNotFound)
	}
}

func (v *APIMockDB) GetENI(mac string) (res *types.ENI, err error) {
	v.eniCache.Range(func(key, value any) bool {
		eni := value.(*ENIKeeper)
		if eni.Mac.String() == mac {
			res = &eni.ENI
			return false
		}
		return true
	})
	if res == nil {
		err = errors.New(apiErr.InvalidEniIdNotFound)
	}
	return
}

func (v *APIMockDB) GetAttachedENIs(withTrunk bool) (total int, eniList []*types.ENI, err error) {
	if !v.readOnlyRateLimiter.TryAccept() {
		return 0, nil, errors.New(apiErr.AccountFlowLimitExceeded)
	}
	v.eniCache.Range(func(key, value any) bool {
		eni := value.(*ENIKeeper)
		if eni.Trunk && !withTrunk {
			return true
		}
		total++
		if eni.celloCreated {
			eniList = append(eniList, &eni.ENI)
		}
		return true
	})
	return
}

func (v *APIMockDB) GetSecondaryENIMACs() ([]string, error) {
	var result []string
	v.eniCache.Range(func(key, value any) bool {
		eni := value.(*ENIKeeper)
		if eni.isPrimary {
			return true
		}
		if eni.Trunk {
			return true
		}

		result = append(result, eni.Mac.String())
		return true
	})
	return result, nil
}

func (v *APIMockDB) GetENIIPList(eniMac string) (ipv4s []net.IP, ipv6s []net.IP, err error) {
	var res *ENIKeeper
	v.eniCache.Range(func(key, value any) bool {
		eni := value.(*ENIKeeper)
		if eni.Mac.String() == eniMac {
			res = eni
			return false
		}
		return true
	})

	res.ipv4s.Range(func(key, value any) bool {
		ip := value.(*goipam.IP).IP.String()
		ipv4s = append(ipv4s, net.ParseIP(ip))
		return true
	})

	res.ipv6s.Range(func(key, value any) bool {
		ip := value.(*goipam.IP).IP.String()
		ipv6s = append(ipv6s, net.ParseIP(ip))
		return true
	})
	return
}

func (v *APIMockDB) AllocIPAddresses(eniID, _ string, v4Cnt, v6Cnt int) (ipv4s []net.IP, ipv6s []net.IP, err error) {
	if !v.writeRateLimiter.TryAccept() {
		return nil, nil, errors.New(apiErr.AccountFlowLimitExceeded)
	}
	poolEni, exist := v.eniCache.Load(eniID)
	if !exist {
		return nil, nil, errors.New(apiErr.InvalidEniIdNotFound)
	}
	eni := poolEni.(*ENIKeeper)

	var v4s, v6s []*goipam.IP

	defer func() {
		if err != nil {
			for _, ip := range v4s {
				_, _ = v.ipam.ReleaseIP(context.Background(), ip)
				_ = eni.removeIPv4(ip)
			}
			for _, ip := range v6s {
				_, _ = v.ipam.ReleaseIP(context.Background(), ip)
				_ = eni.removeIPv6(ip)
			}
		}
	}()

	for i := 0; i < v4Cnt; i++ {
		ip, inErr := v.acquireIP(eni.Subnet.CIDR.IPv4.String())
		if inErr != nil {
			return nil, nil, inErr
		}
		v4s = append(v4s, ip)
		inErr = eni.putIPv4(ip)
		if inErr != nil {
			return nil, nil, inErr
		}
		ipv4s = append(ipv4s, net.ParseIP(ip.IP.String()))
	}

	for i := 0; i < v6Cnt; i++ {
		ip, inErr := v.acquireIP(eni.Subnet.CIDR.IPv6.String())
		if inErr != nil {
			return nil, nil, inErr
		}
		v6s = append(v6s, ip)
		inErr = eni.putIPv6(ip)
		if inErr != nil {
			return nil, nil, inErr
		}
		ipv6s = append(ipv6s, net.ParseIP(ip.IP.String()))
	}
	return
}

func (v *APIMockDB) DeallocIPAddresses(eniID, _ string, ipv4s, ipv6s []net.IP) error {
	if !v.writeRateLimiter.TryAccept() {
		return errors.New(apiErr.AccountFlowLimitExceeded)
	}
	poolEni, exist := v.eniCache.Load(eniID)
	if !exist {
		return errors.New(apiErr.InvalidEniIdNotFound)
	}
	eni := poolEni.(*ENIKeeper)

	// check
	var v4s, v6s []*goipam.IP
	for _, ip := range ipv4s {
		if temp, ok := eni.ipv4s.Load(ip.String()); !ok {
			return errors.New(apiErr.InvalidPrivateIpMalformed)
		} else {
			v4s = append(v4s, temp.(*goipam.IP))
		}
	}
	for _, ip := range ipv6s {
		if temp, ok := eni.ipv6s.Load(ip.String()); !ok {
			return errors.New(apiErr.InvalidIpv6Malformed)
		} else {
			v6s = append(v6s, temp.(*goipam.IP))
		}
	}

	for _, ip := range v4s {
		_ = eni.removeIPv4(ip)

	}
	for _, ip := range v6s {
		_ = eni.removeIPv4(ip)
	}
	return nil
}

func (v *APIMockDB) GetInstanceLimit() (*helper.InstanceLimits, error) {
	if !v.readOnlyRateLimiter.TryAccept() {
		return nil, errors.New(apiErr.AccountFlowLimitExceeded)
	}
	return &v.InstanceLimits, nil
}

func (v *APIMockDB) PutCustomEni(subnet *types.Subnet) (*types.ENI, error) {
	return v.createENI(subnet, []string{GenerateSecurityGroupId()}, false, false, false, 1)
}

func NewAPIMockDB(family types.IPFamily, limits helper.InstanceLimits, ecsSubnet *types.Subnet, subnets []*types.Subnet) (*APIMockDB, error) {
	var err error
	impl := &APIMockDB{
		ipFamily:       family,
		InstanceLimits: limits,
		eniCache:       sync.Map{},
		eniTickets:     make(chan struct{}, limits.ENIQuota),
		subnets:        map[string]*types.Subnet{},
		ipam:           goipam.New(context.TODO()),
		prefixes:       map[string]*goipam.Prefix{},

		readOnlyRateLimiter: flowcontrol.NewTokenBucketRateLimiter(4, 7),
		writeRateLimiter:    flowcontrol.NewTokenBucketRateLimiter(2, 3),
	}

	var totalSubnets []*types.Subnet
	totalSubnets = append(totalSubnets, ecsSubnet)
	totalSubnets = append(totalSubnets, subnets...)

	for _, subnet := range totalSubnets {
		if _, exist := impl.subnets[subnet.ID]; exist {
			continue
		}
		if subnet.CIDR == nil || (subnet.CIDR.IPv4 == nil && subnet.CIDR.IPv6 == nil) {
			return nil, errors.New(apiErr.InvalidParameter)
		}
		if subnet.CIDR.IPv4 != nil {
			impl.subnets[subnet.ID] = subnet
			ipv4Cidr := subnet.CIDR.IPv4.String()
			if _, exist := impl.prefixes[ipv4Cidr]; exist {
				return nil, fmt.Errorf("cidr %s of subnet %s appeared in another subnet", ipv4Cidr, subnet.ID)
			}
			impl.prefixes[ipv4Cidr], err = impl.ipam.NewPrefix(context.Background(), ipv4Cidr)
			if err != nil {
				return nil, err
			}
		}

		if subnet.CIDR.IPv6 != nil {
			ipv6Cidr := subnet.CIDR.IPv6.String()
			if _, exist := impl.prefixes[ipv6Cidr]; exist {
				return nil, fmt.Errorf("cidr %s of subnet %s appeared in another subnet", ipv6Cidr, subnet.ID)
			}
			impl.prefixes[ipv6Cidr], err = impl.ipam.NewPrefix(context.Background(), ipv6Cidr)
			if err != nil {
				return nil, err
			}
		}
	}

	// create primary eni
	_, err = impl.createENI(ecsSubnet, []string{GenerateSecurityGroupId()}, false, true, false, 1)
	if err != nil {
		return nil, err
	}

	return impl, nil
}

const (
	nodeName               = "Fake-Node"
	podPersistencePathFake = "./Resource.db"

	accountId     = "20230101"
	instanceId    = "i-yc4y9hpydckdvala27yw"
	instanceType  = "ecs.g2i.large"
	vpcId         = "vpc-fake-test"
	az            = "cn-guilin-a"
	region        = "cn-guilin-boe"
	primaryENIMac = "00:16:3e:71:7b:68"
	primaryENIId  = "eni-fake134shf29dahda9s"
)

var (
	k8sClient            kubernetes.Interface
	instanceMetaGetter   helper.InstanceMetadataGetter
	instanceMetadataCtrl *gomock.Controller
	ec2Ctrl              *gomock.Controller
	podPersist           PodPersistenceManager
	instanceLimit        *helper.InstanceLimits
	gatewayMac, _        = net.ParseMAC("ee:ff:ff:ff:ff:ff")
	ecsSubnet            *types.Subnet
	subnets              []*types.Subnet
	podSgs               []string
	ec2MockClient        *ec2Mock.MockEC2
	volcApi              helper.VolcAPI
)

func clean() {
	instanceMetadataCtrl.Finish()
	ec2Ctrl.Finish()
	podPersist.Close()
	_ = os.Remove(podPersistencePathFake)
	_ = os.Remove("/var/run/cello")
}

func setup(t *testing.T) error {
	err := os.Mkdir("/var/run/cello", 0755)
	if err != nil && !os.IsExist(err) {
		assert.NoError(t, err)
	}
	_ = os.Setenv(envNodeName, nodeName)
	k8sClient = fake.NewSimpleClientset()

	_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: corev1.NodeSpec{},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeExternalIP,
					Address: "172.16.0.3",
				},
				{
					Type:    corev1.NodeHostName,
					Address: "172.16.0.3",
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	ecsSubnet = &types.Subnet{
		ID: GenerateSubnetId(),
		Gateway: &types.IPSet{
			IPv4: net.ParseIP("172.16.0.1"),
			IPv6: net.ParseIP("2408:1000:abff:ff00::1"),
		},
		GatewayMac: gatewayMac,
		CIDR: &types.IPNetSet{
			IPv4: &net.IPNet{
				IP:   net.ParseIP("172.16.0.0"),
				Mask: net.CIDRMask(18, 32),
			},
			IPv6: &net.IPNet{
				IP:   net.ParseIP("2408:1000:abff:ff00::"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	}

	subnets = append(subnets,
		&types.Subnet{
			ID: GenerateSubnetId(),
			Gateway: &types.IPSet{
				IPv4: net.ParseIP("172.17.0.1"),
				IPv6: net.ParseIP("2408:1000:abff:ff03::1"),
			},
			GatewayMac: gatewayMac,
			CIDR: &types.IPNetSet{
				IPv4: &net.IPNet{
					IP:   net.ParseIP("172.17.0.0"),
					Mask: net.CIDRMask(19, 32),
				},
				IPv6: &net.IPNet{
					IP:   net.ParseIP("2408:1000:abff:ff03::"),
					Mask: net.CIDRMask(64, 128),
				},
			},
		},
		&types.Subnet{
			ID: GenerateSubnetId(),
			Gateway: &types.IPSet{
				IPv4: net.ParseIP("172.16.64.1"),
				IPv6: net.ParseIP("2408:1000:abff:ff01::1"),
			},
			GatewayMac: gatewayMac,
			CIDR: &types.IPNetSet{
				IPv4: &net.IPNet{
					IP:   net.ParseIP("172.16.64.0"),
					Mask: net.CIDRMask(18, 32),
				},
				IPv6: &net.IPNet{
					IP:   net.ParseIP("2408:1000:abff:ff01::"),
					Mask: net.CIDRMask(64, 128),
				},
			},
		},
	)

	var subnetIds []string
	for _, subnet := range subnets {
		subnetIds = append(subnetIds, subnet.ID)
	}

	subnetMap := map[string]*types.Subnet{}
	for _, sb := range subnets {
		subnetMap[sb.ID] = sb
	}

	podSgs = append(podSgs, GenerateSecurityGroupId(), GenerateSecurityGroupId())

	celloConfig := &config.Config{
		RamRole:                     datatype.String("KubernetesNodeRoleForECS"),
		OpenApiAddress:              datatype.String("open-boe-stable.volcengineapi.com"),
		SecurityGroups:              podSgs,
		Subnets:                     subnetIds,
		ReconcileIntervalSec:        datatype.Uint32(config.DefaultReconcileIntervalSec),
		PoolTarget:                  datatype.Uint32(3),
		PoolTargetMin:               datatype.Uint32(5),
		PoolMonitorIntervalSec:      datatype.Uint32(config.DefaultPoolMonitorIntervalSec),
		SubnetStatAgingSec:          datatype.Uint32(config.DefaultSubnetStatAgingSec),
		SubnetStatUpdateIntervalSec: datatype.Uint32(config.DefaultSubnetStatUpdateIntervalSec),
		EnableTrunk:                 datatype.Bool(false),
		NetworkMode:                 datatype.String(config.NetworkModeENIShare),
		IPFamily:                    datatype.String(types.IPFamilyDual),
	}

	configData, _ := json.Marshal(celloConfig)
	_, err = k8sClient.CoreV1().ConfigMaps(config.Namespace).Create(context.Background(), &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cello-config",
			Namespace: config.Namespace,
		},
		Data: map[string]string{
			"conf": string(configData),
		},
		BinaryData: nil,
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	instanceMetadataCtrl = gomock.NewController(t)
	instanceMeta := mock.NewMockInstanceMetadataGetter(instanceMetadataCtrl)
	instanceMeta.EXPECT().GetInstanceId().AnyTimes().Return(instanceId)
	instanceMeta.EXPECT().GetInstanceType().AnyTimes().Return(instanceType)
	instanceMeta.EXPECT().GetVpcId().AnyTimes().Return(vpcId)
	instanceMeta.EXPECT().GetRegion().AnyTimes().Return(region)
	instanceMeta.EXPECT().GetAvailabilityZone().AnyTimes().Return(az)
	instanceMeta.EXPECT().GetPrimaryENIMac().AnyTimes().Return(primaryENIMac)
	instanceMeta.EXPECT().GetPrimaryENIId().AnyTimes().Return(primaryENIId)
	instanceMetaGetter = instanceMeta

	instanceLimit = &helper.InstanceLimits{
		InstanceLimitsAttr: helper.InstanceLimitsAttr{
			ENITotal:       0,
			ENIQuota:       4,
			IPv4MaxPerENI:  10,
			IPv6MaxPerENI:  10,
			TrunkSupported: false,
		},
	}

	ec2Ctrl = gomock.NewController(t)
	ec2MockClient = ec2Mock.NewMockEC2(ec2Ctrl)

	apiMockDB, err := NewAPIMockDB(types.IPFamily(*celloConfig.IPFamily), *instanceLimit, ecsSubnet, subnets)
	if err != nil {
		return err
	}
	volcApi = apiMockDB

	ec2MockClient.EXPECT().DescribeInstanceTypes(gomock.Any()).DoAndReturn(func(input *ecs.DescribeInstanceTypesInput) (*ecs.DescribeInstanceTypesOutput, error) {
		if len(input.InstanceTypes) != 1 && volcengine.StringValue(input.InstanceTypes[0]) != instanceType {
			return &ecs.DescribeInstanceTypesOutput{
				Metadata: &response.ResponseMetadata{
					RequestId: GenerateRequestId(),
					Action:    "DescribeInstanceTypes",
					Version:   "2022-04-01",
					Service:   "ecs",
					Region:    region,
					HTTPCode:  http.StatusOK,
					Error:     nil,
				},
				TotalCount: volcengine.Int32(0),
			}, nil
		}
		return &ecs.DescribeInstanceTypesOutput{
			Metadata: &response.ResponseMetadata{
				RequestId: GenerateRequestId(),
				Action:    "DescribeInstanceTypes",
				Version:   "2022-04-01",
				Service:   "ecs",
				Region:    region,
				HTTPCode:  http.StatusOK,
				Error:     nil,
			},
			InstanceTypes: []*ecs.InstanceTypeForDescribeInstanceTypesOutput{{
				InstanceTypeId: volcengine.String(instanceType),
				Network: &ecs.NetworkForDescribeInstanceTypesOutput{
					MaximumNetworkInterfaces:                       volcengine.Int32(int32(instanceLimit.ENIQuota)),
					MaximumPrivateIpv4AddressesPerNetworkInterface: volcengine.Int32(int32(instanceLimit.IPv4MaxPerENI)),
				},
			}},
			TotalCount: volcengine.Int32(1),
		}, nil
	}).AnyTimes()

	ec2MockClient.EXPECT().DescribeInstances(gomock.Any()).DoAndReturn(func(input *ecs.DescribeInstancesInput) (*ecs.DescribeInstancesOutput, error) {
		if len(input.InstanceTypeIds) != 1 && volcengine.StringValue(input.InstanceTypeIds[0]) != instanceId {
			return &ecs.DescribeInstancesOutput{
				Metadata: &response.ResponseMetadata{
					RequestId: GenerateRequestId(),
					Action:    "DescribeInstances",
					Version:   "2022-04-01",
					Service:   "ecs",
					Region:    region,
					HTTPCode:  http.StatusOK,
					Error:     nil,
				},
				TotalCount: volcengine.Int32(0),
			}, nil
		}
		return &ecs.DescribeInstancesOutput{
			Metadata: &response.ResponseMetadata{
				RequestId: GenerateRequestId(),
				Action:    "DescribeInstances",
				Version:   "2022-04-01",
				Service:   "ecs",
				Region:    region,
				HTTPCode:  http.StatusOK,
				Error:     nil,
			},
			Instances: []*ecs.InstanceForDescribeInstancesOutput{
				{
					InstanceId:      volcengine.String(instanceId),
					InstanceTypeId:  volcengine.String(instanceType),
					RdmaIpAddresses: nil,
					VpcId:           volcengine.String(vpcId),
					ZoneId:          volcengine.String(az),
				},
			},
			TotalCount: volcengine.Int32(1),
		}, nil
	}).AnyTimes()

	ec2MockClient.EXPECT().DescribeSubnets(gomock.Any()).DoAndReturn(func(input *vpc.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error) {
		var result []*ec2.SubnetForDescribeSubnetsOutput
		for _, id := range input.SubnetIds {
			if item, exist := subnetMap[*id]; exist {
				avCnt := int64(apiMockDB.prefixes[item.CIDR.IPv4.String()].Usage().AvailableIPs)
				useCnt := int64(apiMockDB.prefixes[item.CIDR.IPv4.String()].Usage().AcquiredIPs)
				result = append(result, &ec2.SubnetForDescribeSubnetsOutput{
					AccountId:               volcengine.String(accountId),
					AvailableIpAddressCount: volcengine.Int64(avCnt),
					CidrBlock:               volcengine.String(item.CIDR.IPv4.String()),
					Ipv6CidrBlock:           volcengine.String(item.CIDR.IPv6.String()),
					CreationTime:            volcengine.String("2022-02-15T17:36:13+08:00"),
					ProjectName:             volcengine.String("default"),
					Status:                  volcengine.String("Available"),
					SubnetId:                volcengine.String(item.ID),
					SubnetName:              volcengine.String(item.ID),
					TotalIpv4Count:          volcengine.Int64(avCnt + useCnt),
					UpdateTime:              volcengine.String("2022-02-15T17:36:13+08:00"),
					VpcId:                   volcengine.String(vpcId),
					ZoneId:                  volcengine.String(az),
				})
			}
		}
		return &ec2.DescribeSubnetsOutput{
			Metadata: &response.ResponseMetadata{
				RequestId: GenerateRequestId(),
				Action:    "DescribeSubnets",
				Version:   "2022-04-01",
				Service:   "vpc",
				Region:    region,
				HTTPCode:  http.StatusOK,
				Error:     nil,
			},
			PageNumber: volcengine.Int64(1),
			PageSize:   volcengine.Int64(100),
			Subnets:    result,
			TotalCount: volcengine.Int64(int64(len(result))),
		}, nil
	}).AnyTimes()

	ec2MockClient.EXPECT().DescribeSubnetAttributes(gomock.Any()).DoAndReturn(func(input *vpc.DescribeSubnetAttributesInput) (*ec2.DescribeSubnetAttributesOutput, error) {
		metadata := &response.ResponseMetadata{
			RequestId: GenerateRequestId(),
			Action:    "DescribeSubnetAttributes",
			Version:   "2022-04-01",
			Service:   "vpc",
			Region:    region,
			HTTPCode:  http.StatusOK,
			Error:     nil,
		}

		subnet, exist := subnetMap[volcengine.StringValue(input.SubnetId)]
		if !exist {
			metadata.HTTPCode = http.StatusNotFound
			metadata.Error = &response.Error{
				CodeN:   0,
				Code:    apiErr.InvalidSubnetNotFound,
				Message: fmt.Sprintf("subnet %s not found", volcengine.StringValue(input.SubnetId)),
			}
			return &ec2.DescribeSubnetAttributesOutput{
				Metadata: metadata,
			}, apiErr.NewAPIRequestErr(metadata, nil)
		}

		avCnt := int64(apiMockDB.prefixes[subnet.CIDR.IPv4.String()].Usage().AvailableIPs)
		useCnt := int64(apiMockDB.prefixes[subnet.CIDR.IPv4.String()].Usage().AcquiredIPs)

		return &ec2.DescribeSubnetAttributesOutput{
			Metadata:                metadata,
			AccountId:               volcengine.String(accountId),
			AvailableIpAddressCount: volcengine.Int64(avCnt),
			CidrBlock:               volcengine.String(subnet.CIDR.IPv4.String()),
			Ipv6CidrBlock:           volcengine.String(subnet.CIDR.IPv6.String()),
			CreationTime:            volcengine.String("2022-02-15T17:36:13+08:00"),
			ProjectName:             volcengine.String("default"),
			RequestId:               volcengine.String(metadata.RequestId),
			Status:                  volcengine.String("Available"),
			SubnetId:                volcengine.String(subnet.ID),
			SubnetName:              volcengine.String(subnet.ID),
			TotalIpv4Count:          volcengine.Int64(avCnt + useCnt),
			UpdateTime:              volcengine.String("2022-02-15T17:36:13+08:00"),
			VpcId:                   volcengine.String(vpcId),
			ZoneId:                  volcengine.String(az),
		}, nil
	}).AnyTimes()

	return nil
}

func newMockDaemon() (*daemon, error) {
	// k8s
	k8sService, err := k8s.NewK8sService(nodeName, k8sClient)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes service failed: %v", err)
	}

	// cfg
	cfg, err := config.ParseConfig(k8sService)
	if err != nil {
		return nil, fmt.Errorf("parse config failed, %v", err)
	}

	// resource db
	podPersist, err = newPodPersistenceManager(podPersistencePathFake, "pod")
	if err != nil {
		return nil, fmt.Errorf("create persistence db failed: %w", err)
	}

	return newDaemon(k8sService, cfg, ec2MockClient, podPersist, instanceMetaGetter, volcApi, deviceplugin.NewPluginManagerOption().WithDryRun())
}

func TestDaemon(t *testing.T) {
	err := setup(t)
	defer clean()
	assert.NoError(t, err)

	d, err := newMockDaemon()
	assert.NoError(t, err)

	stopCh := make(chan struct{})
	go signalHandler(stopCh)

	pid := os.Getpid()
	signal := syscall.SIGTERM
	prg, err := os.FindProcess(pid)
	assert.NoError(t, err)

	go func() {
		err = d.start(stopCh)
		assert.NoError(t, err)
	}()

	time.Sleep(10 * time.Second)

	t.Run("TestCreateEndpoint", func(t *testing.T) {
		_, err = k8sClient.CoreV1().Pods("default").Create(context.Background(), &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-1",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "my-container",
						Image: "nginx",
					},
				},
			},
			Status: corev1.PodStatus{},
		}, metav1.CreateOptions{})

		assert.NoError(t, err)
		pod, err := k8sClient.CoreV1().Pods("default").Get(context.Background(), "pod-1", metav1.GetOptions{})
		assert.NoError(t, err)
		t.Logf("Pod: %v", pod)

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		resp, err := d.CreateEndpoint(ctx, &pbrpc.CreateEndpointRequest{
			Name:             "pod-1",
			Namespace:        "default",
			InfraContainerId: "11bb1ec3385c2218c41941eef0",
			IfName:           "eth0",
			NetNs:            "cni-b447798f-d564-7d29-8814-715cbd35bd4d",
		})
		t.Logf("resp: %v, err: %v", resp, err)
	})

	t.Run("TestDeleteEndpoint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		resp, err := d.DeleteEndpoint(ctx, &pbrpc.DeleteEndpointRequest{
			Name:             "pod-1",
			Namespace:        "default",
			InfraContainerId: "11bb1ec3385c2218c41941eef0",
		})
		t.Logf("resp: %v, err: %v", resp, err)

		err = k8sClient.CoreV1().Pods("default").Delete(context.Background(), "pod-1", metav1.DeleteOptions{})
		assert.NoError(t, err)
	})

	_ = prg.Signal(signal)
	time.Sleep(10 * time.Second)
}
