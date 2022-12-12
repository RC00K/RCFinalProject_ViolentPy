const express = require('express');
const config = require('../flaskr/config.json');
const randomNumGenerator = require('./utils/randomNum')

// Low and High Ports
let countOfPorts = config.count,
    low = config.range.low,
    high = config.range.high;

// Generate ports
let ports = new Set();

// Ports not in count of ports random low and high
while(ports.size != countOfPorts) {
    ports.add(randomNumGenerator(low, high));
}

console.log(`Starting server at ${countOfPorts} different ports....`)

// Array of ports scanned
let portsArray = [...ports];

// Listening for ports in array of listed ports
for (let index = 0; index < portsArray.length; index++) {
    express().listen(portsArray[index], () => {
        console.log('\n......Started A Server......\n');
    });
}