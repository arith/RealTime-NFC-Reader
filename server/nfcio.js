var nfcIO  = require('rpi-gpio');

var buzzer 		= 37;
var ledDesktop	= 40;
var ledFile		= 38;
var ledDevice   = 36;
var ledAlert    = 32;
var ledTagWrite	= 18;

var buzzerInterval;
var desktopLedInterval;
var fileLedInterval;
var deviceLedInterval;
var alertLedInterval;
var nfcLedInterval;

exports.setup = function(){
	nfcIO.setup(buzzer,nfcIO.DIR_OUT,function(){
		nfcIO.write(buzzer,false,function(err){
			if(err) throw err;
		});
	});
	nfcIO.setup(ledTagWrite,nfcIO.DIR_OUT,function(){
		nfcIO.write(ledTagWrite,false,function(err){
			if(err) throw err;
		});
	});
	nfcIO.setup(ledDesktop,nfcIO.DIR_OUT,function(){
		nfcIO.write(ledDesktop,false,function(err){
			if(err) throw err;
		});
	});
	nfcIO.setup(ledFile,nfcIO.DIR_OUT,function(){
		nfcIO.write(ledFile,false,function(err){
			if(err) throw err;
		});
	});
	nfcIO.setup(ledDevice,nfcIO.DIR_OUT,function(){
		nfcIO.write(ledDevice,false,function(err){
			if(err) throw err;
		});
	});
	nfcIO.setup(ledAlert,nfcIO.DIR_OUT,function(){
		nfcIO.write(ledAlert,false,function(err){
			if(err) throw err;
		});
	});
}

exports.buzzerOn = function(){
	nfcIO.write(buzzer,true,function(err){
		if(err) throw err;
	});
}
exports.buzzerOff = function(){
	nfcIO.write(buzzer,false,function(err){
		if(err) throw err;
	});
}
exports.buzzerBeepStart = function(rate_ms){
	var flip = 0;
	buzzerInterval = setInterval(function(){
		flip = !flip;
		nfcIO.write(buzzer,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.buzzerBeepStop = function(){
	clearInterval(buzzerInterval);
	nfcIO.write(buzzer,false,function(err){
		if(err) throw err;
	});
}

exports.desktopLedOn = function(){
	nfcIO.write(ledDesktop,true,function(err){
		if(err) throw err;
	});
}
exports.desktopLedOff = function(){
	nfcIO.write(ledDesktop,false,function(err){
		if(err) throw err;
	});
}
exports.desktopLedBlinkStart = function(rate_ms){
	var flip = 0;
	desktopLedInterval = setInterval(function(){
		flip = !flip;
		nfcIO.write(ledDesktop,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.desktopLedBlinkStop = function(){
	clearInterval(desktopLedInterval);
	nfcIO.write(ledDesktop,false,function(err){
		if(err) throw err;
	});
}

exports.fileLedOn = function(){
	nfcIO.write(ledFile,true,function(err){
		if(err) throw err;
	});
}
exports.fileLedOff = function(){
	nfcIO.write(ledFile,false,function(err){
		if(err) throw err;
	});
}
exports.fileLedBlinkStart = function(rate_ms){
	var flip = 0;
	fileLedInterval = setInterval(function(){
		flip = !flip;
		nfcIO.write(ledFile,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.fileLedBlinkStop = function(){
	clearInterval(fileLedInterval);
	nfcIO.write(ledFile,false,function(err){
		if(err) throw err;
	});
}

exports.deviceLedOn = function(){
	nfcIO.write(ledDevice,true,function(err){
		if(err) throw err;
	});
}
exports.deviceLedOff = function(){
	nfcIO.write(ledDevice,false,function(err){
		if(err) throw err;
	});
}
exports.deviceLedBlinkStart = function(rate_ms){
	var flip = 0;
	deviceLedInterval = setInterval(function(){
		flip = !flip;
		nfcIO.write(ledDevice,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.deviceLedBlinkStop = function(){
	clearInterval(deviceLedInterval);
	nfcIO.write(ledDevice,false,function(err){
		if(err) throw err;
	});
}

exports.alertLedOn = function(){
	nfcIO.write(ledAlert,true,function(err){
		if(err) throw err;
	});
}
exports.alertLedOff = function(){
	nfcIO.write(ledAlert,false,function(err){
		if(err) throw err;
	});
}
exports.alertLedBlinkStart = function(rate_ms){
	var flip = 0;
	alertLedInterval= setInterval(function(){
		flip = !flip;
		nfcIO.write(ledAlert,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.alertLedBlinkStop = function(){
	clearInterval(alertLedInterval);
	nfcIO.write(ledAlert,false,function(err){
		if(err) throw err;
	});
}

exports.nfcLedOn = function(){
	nfcIO.write(ledTagWrite,true,function(err){
		if(err) throw err;
	});
}
exports.nfcLedOff = function(){
	nfcIO.write(ledTagWrite,true,function(err){
		if(err) throw err;
	});
}
exports.nfcLedBlinkStart = function(rate_ms){
	var flip = 0;
	nfcLedInterval = setInterval(function(){
		flip = !flip;
		nfcIO.write(ledTagWrite,flip,function(err){
			if(err) throw err;
		});
	},rate_ms);
}
exports.nfcLedBlinkStop = function(){
	clearInterval(nfcLedInterval);
	nfcIO.write(ledTagWrite,false,function(err){
		if(err) throw err;
	});
}


