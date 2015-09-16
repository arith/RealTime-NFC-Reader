var app 		= require('express')();
var http 		= require('http').Server(app);
var io 			= require('socket.io')(http);
//===================================================//
var nfcexplore	= require('./nfcexplore');
//var nfcio       = require('./nfcio');

var NFCXPLORE_HOST = '127.0.0.1';
var NFCXPLORE_PORT = 6969;
//===================================================//


nfcexplore.start(NFCXPLORE_HOST,NFCXPLORE_PORT,function(port,nfcEv){

	console.log("NFC Explore was started at port : "+port);

	nfcEv.on('stopped',function(port){
		console.log("NFC Explore was stopped at port : "+port);
	});
	
	nfcEv.on('read',function(jsonString){
		var patientInfo;
		
		try{
			patientInfo = JSON.parse(jsonString);
		}
		catch(err){
			console.log("Error reading tag info : "+err);
			return;
		}
		
		console.log('nfc :'+ 
			'Tag Info Received: \n'+ 
				'\tPatient Id\t:'+patientInfo.patientId+
				'\tTimestamp\t:'+patientInfo.timestamp+
				'\tName\t\t:'+patientInfo.name+
				'\tTel\t\t:'+patientInfo.tel+
				'\tCenter\t\t:'+patientInfo.center+
				'\tBlood\t\t:'+patientInfo.blood+
				'\tInfection\t:'+patientInfo.infection
		);
		
		io.emit('popTagInfo',jsonString);
	});
});


app.get('/',function(req,res){
	res.sendFile(__dirname+'/nfcclient.html');
});

io.on('connection',function(socket){

	console.log('http: A user is connected');
	
	socket.on('disconnect',function(){
		console.log('http: A user is disconnected');
		if(typeof nfcexplore == 'undefined'){
			console.log('nfc: Nfcexplore undefined');
			return;
		}
		console.log('nfc: Cancelling write');
		nfcexplore.writeCancel(function(){
			console.log('nfc: Write cancelled');
		});
	});
	
	socket.on('pushTagInfo',function(msgJson){
		nfcexplore.write(msgJson,function(errMsg,writtenJsonText){
			console.log("Tag Write Done status :"+errMsg);
			if(errMsg==="success"){
				io.emit('serverMsg',"Message: Tag was written successfully");
				return;
			}
			if(errMsg==="cancelled"){
				io.emit('serverMsg',"Message: Tag write operation was cancelled");
				return;
			}
			io.emit('serverMsg',"Message: Error ( "+errMsg+" )");
		});
		
		var patientInfo;
		
		try{
			var patientInfo = JSON.parse(msgJson);
		}
		catch(err){
			console.log(err);
			return;
		}
		
		console.log('http : Tag Info Received: \n'+ 
		            '\tPatient Id\t:'+patientInfo.patientId+
					'\tTimestamp\t:'+patientInfo.timestamp+
					'\tName\t\t:'+patientInfo.name+
					'\tTel\t\t:'+patientInfo.tel+
					'\tCenter\t\t:'+patientInfo.center+
					'\tBlood\t\t:'+patientInfo.blood+
					'\tInfection\t:'+patientInfo.infection
		);

		io.emit('serverMsg',"Message: Place NFC tag on the device and wait...");
	});
});

http.listen(3000,function(){
	console.log('http: Listening on port :3000');
});

