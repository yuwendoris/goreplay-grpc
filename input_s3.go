package main

import (
    _ "bufio"
    "fmt"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
    _ "github.com/aws/aws-sdk-go/service/s3/s3manager"
    "io"
    "log"
    "math/rand"
    "os"
    "path/filepath"
    "strings"
    "sort"
    "crypto/sha1"
    "encoding/hex"
)

type S3InputConfig struct {
    bufferConfig FileInputConfig

    bufferPath string
    region     string
    endpoint   string
}

// FileOutput output plugin
type S3Output struct {
    pathTemplate string

    buffer  *FileInput
    session *session.Session
    config  *S3InputConfig
}

// NewFileOutput constructor for FileOutput, accepts path
func NewS3Input(pathTemplate string, config *S3InputConfig) *S3Input {
    o := new(S3Input)
    o.pathTemplate = pathTemplate
    o.config = config

    if config.region == "" {
        config.region = "us-east-1"
    }

    if config.bufferPath == "" {
        config.bufferPath = "/tmp"
    }

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

type sortByS3FileIndex []*s3.Object

func (s sortByS3FileIndex) Len() int {
    return len(s)
}

func (s sortByS3FileIndex) Swap(i, j int) {
    s[i], s[j] = s[j], s[i]
}

func (s sortByS3FileIndex) Less(i, j int) bool {
    if withoutIndex(*s[i].Key) == withoutIndex(*s[j].Key) {
        return getFileIndex(*s[i].Key) < getFileIndex(*s[j].Key)
    }

    return s[i] < s[j]
}

func (o *S3Input) updateBuffer() (err error) {
    path := o.pathTemplate[5:] // stripping `s3://`
    sep := strings.IndexByte(path, '/')

    bucket = path[:sep]
    key = path[sep+1:]

    params := &s3.ListObjectsInput{
        Bucket: bucket,
        Prefix: key,
    }
    resp, err := svc.ListObjects(params)
    sort.Sort(sortByS3FileIndex(resp.Contents))

    if err != nil {
        return err
    }

    if o.buffer.currentFile == nil {
        fileToDownload := resp.Contents[0]
    } else {
        found := false

        bufName := filepath.Base(i.buffer.currentFile.Name())
        bufHex := strings.TrimSuffix(bufName, filepath.Ext(bufName))
        bufSha, _ := hex.DecodeString(bufHex)

        for idx, c := range resp.Contents {
            sha := sha1.Sum(*c.Key)[0:]

            if bytes.Equal(bufSha, sha) && idx != len(matches)-1 {
                if i.buffer.currentFile, err = os.Open(matches[idx+1]); err != nil {
                    log.Println("Can't read file ", matches[idx+1], err)
                    return
                }

                found = true
            }
        }

        if !found {
            return new(NextFileNotFound)
        }
    }


    if strings.HasSuffix(o.pathTemplate, ".gz") {
        buffer_name += ".gz"
    }

    buffer_path := filepath.Join(o.config.bufferPath, buffer_name)
}

func (o *S3Output) Read(data []byte) (int, error) {
    return o.buffer.Read(data)
}

func (o *S3Output) String() string {
    return "S3 Input: " + o.file.Name()
}

func (o *S3Output) Close() {
    o.buffer.Close()
}

func (o *S3Output) keyPath(idx int) (bucket, key string) {
    path := o.pathTemplate[5:] // stripping `s3://`
    sep := strings.IndexByte(path, '/')

    bucket = path[:sep]
    key = path[sep+1:]

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
}
