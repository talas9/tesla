#!/usr/bin/env node
const express = require('express')
const fs = require("fs");
const md5File = require('md5-file')
const cors = require('cors')
const app = express()

const bodyParser = require('body-parser');
app.use(cors())	
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.raw());

/*
Usage: 
Install nodejs and npm

npm install 
node firmware_server.js

On MCU side:
1. nc 192.168.90.100 25956
2. set_handshake 5.75.227.121 8080
3. install <URL>
4. enjoy 


INTEL MCU2 from APE PORT set 192.168.90.103
INTEL ICE from APE PORT using BroadR-Reach Adapter set 192.168.90.103
/*




//* SETTINGS */

const host = "159.69.21.1"; // ip of pc
const port = 8080;
const DEBUG = true; 
const LOCAL = true; //File serving 

if(LOCAL)
	app.use(express.static('./'));

var logger = function(req, res, next) {
    console.log("GOT REQUEST !");
    console.log(req.path);
    console.log(req.body);
    next();
}

app.use(logger);

let signatures;
try{
	signatures = JSON.parse(fs.readFileSync('signatures.json'));
}catch(e){
	console.log("Cant open sig file signatures.json");
	process.exit(1);
}



let createResponse = (sig)=>{
	let signature = sig.signature;
	let url = sig.downloadUrl;
	let md5 = sig.md5;
	if(!md5){
		md5 = md5File.sync(sig.path);
	}
	return {
		ssq_download_file_md5: md5,
		ssq_download_sig: signature,
		ssq_download_url: url,
        vehicle_job_status_url:`http://${host}:${port}/status`
	}
}

app.get('/packages/signature', (req, res) => {
	let signature = req.body.signature;
	if(DEBUG)
		console.log("# New Request with signature : "+ signature);
		signature = signatures.find(i=>i.signature===signature)
		if(signature){
			
			let response = createResponse(signature);
			if(DEBUG)
				console.log(response);
			res.json(response);
			return


		}
		console.log("Can't find right image!");
		res.status(404).send();
})

app.all('/status',(req,res) => {
	console.log('car-log',req.body);
	res.json({});
})



app.listen(port, () => console.log(`Firmware backend service listening on port ${port}!`))
