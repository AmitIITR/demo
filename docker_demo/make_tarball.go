package main

import (
   "archive/tar"
   "fmt"
   "io"
   "os"
   "path/filepath"
)

func checkerror(err error) {
   if err != nil {
      fmt.Println(err)
      //os.Exit(1)
   }
}

//link for code: https://ispycode.com/Blog/golang/2016-10/Archive-directory-with-tar
func makeTarball() {

   destinationfile := "ra.tar"
   sourcedir := "/home/ec2-user/java_agent"

   dir, err := os.Open(sourcedir)
   checkerror(err)
   defer dir.Close()

   // get list of files
   files, err := dir.Readdir(0)
   checkerror(err)

   // create tar file
   tarfile, err := os.Create(destinationfile)
   checkerror(err)
   defer tarfile.Close()

   var fileWriter io.WriteCloser = tarfile

   tarfileWriter := tar.NewWriter(fileWriter)
   defer tarfileWriter.Close()

   for _, fileInfo := range files {

      if fileInfo.IsDir() {
         continue
      }

      file, err := os.Open(dir.Name() + string(filepath.Separator) + fileInfo.Name())
      checkerror(err)
      defer file.Close()

      // prepare the tar header
      header := new(tar.Header)
      header.Name = file.Name()
      header.Size = fileInfo.Size()
      header.Mode = int64(fileInfo.Mode())
      header.ModTime = fileInfo.ModTime()

      err = tarfileWriter.WriteHeader(header)
      checkerror(err)

      _, err = io.Copy(tarfileWriter, file)
      checkerror(err)
   }
}
