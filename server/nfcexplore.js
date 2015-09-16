var nfcIO  		= require('./nfcio');
var net 		= require('net');
var event   	= require('events');
var nfcevent 	= new event.EventEmitter();

var nfcXploreWrFlag 		= false;
var nfcXploreWrJason		= null;
var nfcXploreWrDoneCallback = null;

nfcIO.setup();

exports.start = function(host,port,startCallback){
	net.createServer(function(socket){
		
		socket.on('data',function(buffer){
			var cmdStr = buffer.toString('ascii');
		
			if(cmdStr=="write_request"){
				if(nfcXploreWrFlag==false){
					socket.write("0");
					return;
				}
				nfcXploreWrFlag = false;
				
				setTimeout(function(){
					socket.write("1");
					setTimeout(function(){
						socket.write(nfcXploreWrJason);
					},50);
				},50);
				nfcevent.emit('written','success',nfcXploreWrJason);
				return;
			}
			
			if(cmdStr=="ping_request"){
				socket.write("ok");
				return;
			}
			
			nfcevent.emit('read',buffer.toString('ascii'));
		});
		
		socket.on('close',function(data){
			nfcevent.emit('stopped',port);
		});
		
		startCallback(port,nfcevent);
	}).listen(port,host);
	
	return nfcevent;
}

exports.write = function(jsonTxt,wrDoneCallback){
	nfcXploreWrDoneCallback = wrDoneCallback;
	try{
		var jsonStr = JSON.parse(jsonTxt);
	}
	catch(err){
		nfcevent.emit('written','fail',null);
		return nfcevent;
	}
	nfcIO.nfcLedBlinkStart(250);
	nfcIO.buzzerOn();
	setTimeout(function(){
		nfcIO.buzzerOff();
	},500);
	
	nfcXploreWrFlag   	= true;
	nfcXploreWrJason 	= jsonTxt;
	
	return nfcevent;
}

exports.writeCancel = function(){
	nfcXploreWrFlag   	= false;
	nfcXploreWrJason 	= null;
	
	nfcevent.emit('written','cancelled',null);
}


nfcevent.on('written',function(msg,json){
	if(typeof nfcXploreWrDoneCallback != 'function'){
		return;
	}
	nfcIO.nfcLedBlinkStop();
	nfcXploreWrDoneCallback(msg,json);
});
