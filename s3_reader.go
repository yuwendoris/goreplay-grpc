package main

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3ReadCloser struct {
	bucket    string
	key       string
	offset    int
	totalSize int
	readBytes int
	sess      *session.Session
	buf       *bytes.Buffer
}

func awsConfig() *aws.Config {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
	}

	config := &aws.Config{Region: aws.String(region)}

	if endpoint := os.Getenv("AWS_ENDPOINT_URL"); endpoint != "" {
		config.Endpoint = aws.String(endpoint)
		log.Println("Custom endpoint:", endpoint)
	}

	log.Println("Connecting to S3. Region: " + region)

	config.CredentialsChainVerboseErrors = aws.Bool(true)

	if os.Getenv("AWS_DEBUG") != "" {
		config.LogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody)
	}

	return config
}

func NewS3ReadCloser(path string) *S3ReadCloser {
	if !PRO {
		log.Fatal("Using S3 input and output require PRO license")
		return nil
	}

	bucket, key := parseS3Url(path)
	sess := session.Must(session.NewSession(awsConfig()))

	log.Println("[S3 Input] S3 connection succesfully initialized", path)

	return &S3ReadCloser{
		bucket: bucket,
		key:    key,
		sess:   sess,
		buf:    &bytes.Buffer{},
	}
}

func (s *S3ReadCloser) Read(b []byte) (n int, e error) {
	if s.readBytes == 0 || s.readBytes+len(b) > s.offset {
		svc := s3.New(s.sess)

		objectRange := "bytes=" + strconv.Itoa(s.offset)
		s.offset += 1000000 // Reading in chunks of 1 mb
		objectRange += "-" + strconv.Itoa(s.offset-1)

		params := &s3.GetObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(s.key),
			Range:  aws.String(objectRange),
		}
		resp, err := svc.GetObject(params)

		if err != nil {
			log.Println("[S3 Input] Error during getting file", s.bucket, s.key, err)
		} else {
			s.totalSize, _ = strconv.Atoi(strings.Split(*resp.ContentRange, "/")[1])
			s.buf.ReadFrom(resp.Body)
		}
	}

	s.readBytes += len(b)

	return s.buf.Read(b)
}

func (s *S3ReadCloser) Close() error {
	return nil
}
