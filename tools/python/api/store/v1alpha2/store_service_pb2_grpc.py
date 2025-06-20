# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
from store.v1alpha2 import object_pb2 as store_dot_v1alpha2_dot_object__pb2


class StoreServiceStub(object):
    """Defines an interface for content-addressable storage
    service for arbitrary objects such as blobs, files, etc.
    It may also store metadata for pushed objects.

    Store service can be implemented by various storage backends,
    such as local file system, OCI registry, etc.

    Middleware should be used to control who can perform these RPCs.
    Policies for the middleware can be handled via separate service.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Push = channel.stream_unary(
                '/store.v1alpha2.StoreService/Push',
                request_serializer=store_dot_v1alpha2_dot_object__pb2.Object.SerializeToString,
                response_deserializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.FromString,
                _registered_method=True)
        self.Pull = channel.unary_stream(
                '/store.v1alpha2.StoreService/Pull',
                request_serializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
                response_deserializer=store_dot_v1alpha2_dot_object__pb2.Object.FromString,
                _registered_method=True)
        self.Lookup = channel.unary_unary(
                '/store.v1alpha2.StoreService/Lookup',
                request_serializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
                response_deserializer=store_dot_v1alpha2_dot_object__pb2.Object.FromString,
                _registered_method=True)
        self.Delete = channel.unary_unary(
                '/store.v1alpha2.StoreService/Delete',
                request_serializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
                response_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
                _registered_method=True)


class StoreServiceServicer(object):
    """Defines an interface for content-addressable storage
    service for arbitrary objects such as blobs, files, etc.
    It may also store metadata for pushed objects.

    Store service can be implemented by various storage backends,
    such as local file system, OCI registry, etc.

    Middleware should be used to control who can perform these RPCs.
    Policies for the middleware can be handled via separate service.
    """

    def Push(self, request_iterator, context):
        """Push performs streamed write operation for the provided object.
        Objects must be sent in chunks if larger than 4MB.
        All objects are stored in raw format.

        Some object types such as OASF records may be validated.
        CID is ignored and is generated by the service.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Pull(self, request, context):
        """Pull performs streamed read operation for the requested object.
        Object is sent back in chunks if larger than 4MB.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Lookup(self, request, context):
        """Lookup resolves basic metadata for the object.
        It does not return the object data.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Delete(self, request, context):
        """Remove performs delete operation for the requested object.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_StoreServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'Push': grpc.stream_unary_rpc_method_handler(
                    servicer.Push,
                    request_deserializer=store_dot_v1alpha2_dot_object__pb2.Object.FromString,
                    response_serializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
            ),
            'Pull': grpc.unary_stream_rpc_method_handler(
                    servicer.Pull,
                    request_deserializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.FromString,
                    response_serializer=store_dot_v1alpha2_dot_object__pb2.Object.SerializeToString,
            ),
            'Lookup': grpc.unary_unary_rpc_method_handler(
                    servicer.Lookup,
                    request_deserializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.FromString,
                    response_serializer=store_dot_v1alpha2_dot_object__pb2.Object.SerializeToString,
            ),
            'Delete': grpc.unary_unary_rpc_method_handler(
                    servicer.Delete,
                    request_deserializer=store_dot_v1alpha2_dot_object__pb2.ObjectRef.FromString,
                    response_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'store.v1alpha2.StoreService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('store.v1alpha2.StoreService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class StoreService(object):
    """Defines an interface for content-addressable storage
    service for arbitrary objects such as blobs, files, etc.
    It may also store metadata for pushed objects.

    Store service can be implemented by various storage backends,
    such as local file system, OCI registry, etc.

    Middleware should be used to control who can perform these RPCs.
    Policies for the middleware can be handled via separate service.
    """

    @staticmethod
    def Push(request_iterator,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.stream_unary(
            request_iterator,
            target,
            '/store.v1alpha2.StoreService/Push',
            store_dot_v1alpha2_dot_object__pb2.Object.SerializeToString,
            store_dot_v1alpha2_dot_object__pb2.ObjectRef.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Pull(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(
            request,
            target,
            '/store.v1alpha2.StoreService/Pull',
            store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
            store_dot_v1alpha2_dot_object__pb2.Object.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Lookup(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/store.v1alpha2.StoreService/Lookup',
            store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
            store_dot_v1alpha2_dot_object__pb2.Object.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Delete(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/store.v1alpha2.StoreService/Delete',
            store_dot_v1alpha2_dot_object__pb2.ObjectRef.SerializeToString,
            google_dot_protobuf_dot_empty__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
