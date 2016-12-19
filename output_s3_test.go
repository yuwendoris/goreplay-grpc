package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestS3Output(t *testing.T) {
	bucket := aws.String("test-gor")
	rnd := rand.Int63()
	path := fmt.Sprintf("s3://test-gor/%d/requests.gz", rnd)

	output := NewS3Output(path,
		&S3OutputConfig{
			bufferConfig: FileOutputConfig{queueLimit: 2},
		},
	)

	svc := s3.New(output.session)

	output.Write([]byte("1 1 1\ntest"))
	output.Write([]byte("1 1 1\ntest"))
	output.buffer.updateName()
	output.Write([]byte("1 1 1\ntest"))
	output.Write([]byte("1 1 1\ntest"))
	output.buffer.updateName()
	output.Write([]byte("1 1 1\ntest"))

	time.Sleep(time.Second)

	params := &s3.ListObjectsInput{
		Bucket: bucket,
		Prefix: aws.String(fmt.Sprintf("%d", rnd)),
	}

	resp, _ := svc.ListObjects(params)
	if len(resp.Contents) != 2 {
		t.Error("Should create 2 objects", len(resp.Contents))
	} else {
		if *resp.Contents[0].Key != fmt.Sprintf("%d/requests_0.gz", rnd) ||
			*resp.Contents[1].Key != fmt.Sprintf("%d/requests_1.gz", rnd) {
			t.Error("Should assign proper names", resp.Contents)
		}
	}

	for _, c := range resp.Contents {
		svc.DeleteObject(&s3.DeleteObjectInput{Bucket: bucket, Key: c.Key})
	}

	matches, _ := filepath.Glob(fmt.Sprintf("/tmp/gor_output_s3_*"))
	for _, m := range matches {
		os.Remove(m)
	}
}
