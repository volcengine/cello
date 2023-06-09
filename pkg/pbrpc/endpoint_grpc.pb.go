// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: endpoint.proto

package pbrpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CelloClient is the client API for Cello service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CelloClient interface {
	CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error)
	DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error)
	GetPodMetaInfo(ctx context.Context, in *GetPodMetaRequest, opts ...grpc.CallOption) (*GetPodMetaResponse, error)
	PatchPodAnnotation(ctx context.Context, in *PatchPodAnnotationRequest, opts ...grpc.CallOption) (*PatchPodAnnotationResponse, error)
}

type celloClient struct {
	cc grpc.ClientConnInterface
}

func NewCelloClient(cc grpc.ClientConnInterface) CelloClient {
	return &celloClient{cc}
}

func (c *celloClient) CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error) {
	out := new(CreateEndpointResponse)
	err := c.cc.Invoke(ctx, "/endpoint.Cello/CreateEndpoint", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *celloClient) DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error) {
	out := new(DeleteEndpointResponse)
	err := c.cc.Invoke(ctx, "/endpoint.Cello/DeleteEndpoint", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *celloClient) GetPodMetaInfo(ctx context.Context, in *GetPodMetaRequest, opts ...grpc.CallOption) (*GetPodMetaResponse, error) {
	out := new(GetPodMetaResponse)
	err := c.cc.Invoke(ctx, "/endpoint.Cello/GetPodMetaInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *celloClient) PatchPodAnnotation(ctx context.Context, in *PatchPodAnnotationRequest, opts ...grpc.CallOption) (*PatchPodAnnotationResponse, error) {
	out := new(PatchPodAnnotationResponse)
	err := c.cc.Invoke(ctx, "/endpoint.Cello/PatchPodAnnotation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CelloServer is the server API for Cello service.
// All implementations must embed UnimplementedCelloServer
// for forward compatibility.
type CelloServer interface {
	CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error)
	DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error)
	GetPodMetaInfo(context.Context, *GetPodMetaRequest) (*GetPodMetaResponse, error)
	PatchPodAnnotation(context.Context, *PatchPodAnnotationRequest) (*PatchPodAnnotationResponse, error)
	mustEmbedUnimplementedCelloServer()
}

// UnimplementedCelloServer must be embedded to have forward compatible implementations.
type UnimplementedCelloServer struct {
}

func (UnimplementedCelloServer) CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEndpoint not implemented")
}
func (UnimplementedCelloServer) DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteEndpoint not implemented")
}
func (UnimplementedCelloServer) GetPodMetaInfo(context.Context, *GetPodMetaRequest) (*GetPodMetaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPodMetaInfo not implemented")
}
func (UnimplementedCelloServer) PatchPodAnnotation(context.Context, *PatchPodAnnotationRequest) (*PatchPodAnnotationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PatchPodAnnotation not implemented")
}
func (UnimplementedCelloServer) mustEmbedUnimplementedCelloServer() {}

// UnsafeCelloServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CelloServer will
// result in compilation errors.
type UnsafeCelloServer interface {
	mustEmbedUnimplementedCelloServer()
}

func RegisterCelloServer(s grpc.ServiceRegistrar, srv CelloServer) {
	s.RegisterService(&Cello_ServiceDesc, srv)
}

func _Cello_CreateEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CelloServer).CreateEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/endpoint.Cello/CreateEndpoint",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CelloServer).CreateEndpoint(ctx, req.(*CreateEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cello_DeleteEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CelloServer).DeleteEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/endpoint.Cello/DeleteEndpoint",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CelloServer).DeleteEndpoint(ctx, req.(*DeleteEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cello_GetPodMetaInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPodMetaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CelloServer).GetPodMetaInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/endpoint.Cello/GetPodMetaInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CelloServer).GetPodMetaInfo(ctx, req.(*GetPodMetaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cello_PatchPodAnnotation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PatchPodAnnotationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CelloServer).PatchPodAnnotation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/endpoint.Cello/PatchPodAnnotation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CelloServer).PatchPodAnnotation(ctx, req.(*PatchPodAnnotationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Cello_ServiceDesc is the grpc.ServiceDesc for Cello service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy).
var Cello_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "endpoint.Cello",
	HandlerType: (*CelloServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateEndpoint",
			Handler:    _Cello_CreateEndpoint_Handler,
		},
		{
			MethodName: "DeleteEndpoint",
			Handler:    _Cello_DeleteEndpoint_Handler,
		},
		{
			MethodName: "GetPodMetaInfo",
			Handler:    _Cello_GetPodMetaInfo_Handler,
		},
		{
			MethodName: "PatchPodAnnotation",
			Handler:    _Cello_PatchPodAnnotation_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "endpoint.proto",
}
