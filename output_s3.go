package main

import (
	_ "bufio"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	_ "github.com/aws/aws-sdk-go/service/s3/s3manager"
	_ "io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

type S3OutputConfig struct {
	bufferConfig FileOutputConfig

	bufferPath string
	region     string
	endpoint   string
}

// FileOutput output plugin
type S3Output struct {
	pathTemplate string

	buffer  *FileOutput
	session *session.Session
	config  *S3OutputConfig
	closeC  chan struct{}
}

// NewFileOutput constructor for FileOutput, accepts path
func NewS3Output(pathTemplate string, config *S3OutputConfig) *S3Output {
	o := new(S3Output)
	o.pathTemplate = pathTemplate
	o.config = config
	o.config.bufferConfig.onClose = o.onBufferUpdate

	if config.region == "" {
		config.region = "us-east-1"
	}

	if config.bufferPath == "" {
		config.bufferPath = "/tmp"
	}

	rnd := rand.Int63()
	buffer_name := fmt.Sprintf("gor_output_s3_%d_buf", rnd)

	if strings.HasSuffix(o.pathTemplate, ".gz") {
		buffer_name += ".gz"
	}

	buffer_path := filepath.Join(config.bufferPath, buffer_name)

	o.buffer = NewFileOutput(buffer_path, &config.bufferConfig)
	o.connect()

	if !strings.HasPrefix(pathTemplate, "s3://") {
		log.Fatal("S3 path format should be: s3://<bucket>/<path_format>")
	}

	return o
}

func (o *S3Output) connect() {
	if o.session == nil {
		o.session = session.New(&aws.Config{Region: aws.String(o.config.region)})
	}
}

func (o *S3Output) Write(data []byte) (n int, err error) {
	return o.buffer.Write(data)
}

func (o *S3Output) String() string {
	return "S3 output: " + o.pathTemplate
}

func (o *S3Output) Close() {
	o.buffer.Close()
}

func parseS3Url(path string) (bucket, key string) {
	path = path[5:] // stripping `s3://`
	sep := strings.IndexByte(path, '/')

	bucket = path[:sep]
	key = path[sep+1:]

	return bucket, key
}

func (o *S3Output) keyPath(idx int) (bucket, key string) {
	bucket, key = parseS3Url(o.pathTemplate)

	for name, fn := range dateFileNameFuncs {
		key = strings.Replace(key, name, fn(), -1)
	}

	key = setFileIndex(key, idx)

	return
}

func (o *S3Output) onBufferUpdate(path string) {
	svc := s3.New(o.session)
	idx := getFileIndex(path)
	bucket, key := o.keyPath(idx)

	file, _ := os.Open(path)
	// reader := bufio.NewReader(file)

	_, err := svc.PutObject(&s3.PutObjectInput{
		Body:   file,
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Printf("Failed to upload data to %s/%s, %s\n", bucket, key, err)
		return
	}

	os.Remove(path)

	if o.closeC != nil {
		o.closeC <- struct{}{}
	}
}
