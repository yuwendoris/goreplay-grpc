package http2_protocol

type ReqHeader struct {
	Method string
	Scheme string
}

type Request struct {
	Header ReqHeader
	Data []interface{}
}

type Response struct {
	Header RespHeader
	Data RespData
}

type RespHeader struct {
	Status string
}

type RespData struct {
	DataType string
	Data []interface{}
}