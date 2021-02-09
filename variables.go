package main

var plVersion string = "0.0.7"
var readConfig *Config

// BUFFERSIZE is for copying files
var BUFFERSIZE int64 = 4096 // 4096 bits = default page size on OSX

const serverUA = "PilotLight/0.1"
