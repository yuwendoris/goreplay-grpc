package testg

import (
	"context"
	"fmt"
	"github.com/buger/goreplay/testg/helloworld"
	"github.com/buger/goreplay/testg/routeguide"
	pb "github.com/golang/protobuf/proto"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/runtime/protoiface"
	"io"
	"log"
	"reflect"
	"strings"
	"time"
	"unsafe"
)

var clientRegistry = make(map[string]interface{})

func registerClient(typedNil interface{}) {
	t := reflect.TypeOf(typedNil).Elem()
	clientRegistry[t.PkgPath()+"."+t.Name()] = typedNil
}

func makeInstance(name string) interface{} {
	return clientRegistry[name]
}

func init() {
	conn, _ := grpc.Dial("localhost", grpc.WithInsecure())
	registerClient(helloworld.NewGreeterClient(conn))
	registerClient(routeguide.NewRouteGuideClient(conn))
}

func GetClient(conn *grpc.ClientConn, targetPackage string, object string) interface{} {
	client := makeInstance("github.com/buger/goreplay/testg/" + targetPackage + "." + object + "Client")

	val := reflect.ValueOf(client).Elem().FieldByName("cc")
	reflect.NewAt(val.Type(), unsafe.Pointer(val.UnsafeAddr())).Elem().Set(reflect.ValueOf(conn))

	return client
}

func GetMessage(name string) reflect.Type {
	pt := pb.MessageType(name)

	return pt
}

func AnalysisPath(path string) (string, string, string) {
	pathBlock := strings.Split(path, "/")
	method := pathBlock[len(pathBlock)-1]
	serviceBlock := strings.Split(pathBlock[len(pathBlock)-2], ".")
	targetPackage := serviceBlock[0]
	service := serviceBlock[1]

	return targetPackage, service, method
}

func GetRpcInAndOutType(targetPackage string, service string, method string) (*desc.MessageDescriptor, *desc.MessageDescriptor) {

	inputType := GetRpcDescriptor(targetPackage, service, method).GetInputType()
	outputType := GetRpcDescriptor(targetPackage, service, method).GetOutputType()

	return inputType, outputType
}

func GetRpcDescriptor(targetPackage string, service string, method string) *desc.MethodDescriptor {
	// 文件反向解析
	filename := "./testg/" + targetPackage + "/" + targetPackage + ".proto"

	Parser := protoparse.Parser{}
	descs, err := Parser.ParseFiles(filename)
	if err != nil {
		fmt.Println(err)
	}

	rpc := descs[0].FindService(targetPackage + "." + service).FindMethodByName(method)

	return rpc
}

func GetMessageClient(message reflect.Type) reflect.Value {
	return reflect.New(message.Elem())
}

func ResetElemValue(messageClient reflect.Value, fieldName string, value string) {
	messageClient.Elem().FieldByName(fieldName).Set(reflect.ValueOf(value))
}

func GetMessageObj(targetPackage string, messageType *desc.MessageDescriptor) protoiface.MessageV1 {
	pt := GetMessage(targetPackage + "." + messageType.GetName())

	messageObj := reflect.New(pt.Elem()).Interface().(pb.Message)

	return messageObj
}

func CallMethod(client interface{}, targetPackage string, method string, rpcDescriptor *desc.MethodDescriptor, inputList []interface{}) ([]reflect.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response := []reflect.Value{}

	clientStream := rpcDescriptor.IsClientStreaming()
	serverStream := rpcDescriptor.IsServerStreaming()
	rpc := reflect.ValueOf(client).MethodByName(method)
	if !clientStream && !serverStream {
		//obj := GetMessageObj(targetPackage, rpcDescriptor.GetInputType())
		//pb.Unmarshal(inputList[0], obj)

		in := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(inputList[0])}

		responses := rpc.Call(in)
		response[0] = responses[1]

		return response, fmt.Errorf("%e", responses[1].Interface())
	} else if clientStream && !serverStream {
		in := []reflect.Value{reflect.ValueOf(ctx)}
		responses := rpc.Call(in)
		stream := reflect.ValueOf(responses[0])
		err := responses[1].Interface()

		if err != nil {
			log.Fatalf("%v.RecordRoute(_) = _, %v", client, err)
		}

		for _, point := range inputList {
			in := []reflect.Value{reflect.ValueOf(point)}
			if err := stream.MethodByName("Send").Call(in); err != nil {
				log.Fatalf("%v.Send(%v) = %v", stream, point, err)
			}
		}
		res := stream.MethodByName("CloseAndRecv").Call(nil)

		response[0] = res[1]
		return response, fmt.Errorf("%e", res[1].Interface())
	} else if !clientStream && serverStream {
		//obj := GetMessageObj(targetPackage, rpcDescriptor.GetInputType())
		//pb.Unmarshal(inputList[0], obj)
		in := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(inputList[0])}
		responses := rpc.Call(in)
		stream := reflect.ValueOf(responses[0])
		err := responses[1].Interface()
		if err != nil {
			log.Fatalf("%v.ListFeatures(_) = _, %v", client, err)
		}

		i := 0
		for {
			i++
			res := stream.MethodByName("Recv").Call(nil)
			if res[1].Interface() == io.EOF {
				break
			}

			response[i] = res[0]
			if err != nil {
				log.Fatalf("%v.ListFeatures(_) = _, %v", client, err)
			}
		}

		return response, nil
	} else if clientStream && serverStream {
		in := []reflect.Value{reflect.ValueOf(ctx)}
		responses := rpc.Call(in)
		stream := reflect.ValueOf(responses[0])
		err := responses[1].Interface()
		if err != nil {
			log.Fatalf("%v.RouteChat(_) = _, %v", client, err)
		}
		waitc := make(chan struct{})
		resc := make(chan reflect.Value, 1000)
		go func() {
			for {
				res := stream.MethodByName("Recv").Call(nil)
				if res[1].Interface() == io.EOF {
					// read done.
					close(waitc)
					return
				}
				resc <- res[0]
				if err != nil {
					log.Fatalf("Failed to receive a note : %v", err)
				}
			}
		}()
		for _, note := range inputList {
			in := []reflect.Value{reflect.ValueOf(note)}
			if err := stream.MethodByName("Send").Call(in); err != nil {
				log.Fatalf("Failed to send a note: %v", err)
			}
		}

		stream.MethodByName("CloseSend").Call(nil)

		<-waitc

		i := 0
		for {
			select {
			case data := <-resc:
				i++
				response[i] = data
				break
			case <-waitc:
				break
			}
		}

		return response, nil
	}

	return nil, nil
}
