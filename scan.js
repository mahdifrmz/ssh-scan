#!/usr/bin/node
const net = require('net')
const { exit, argv } = require('process')

const MATCH_REMAIN = 0
const MATCH_SUCCESS = 1
const MATCH_FAILURE = -1

const CONNECTION_TIMEOUT = 5000
const SCANNING_STEP = 1024

const portRange = {
    from: 1,
    to: 0xffff
}

class Matcher{
    constructor(pattern)
    {
        this.pattern = pattern.split('')
    }
    read(input)
    {
        for(const ch of input.split(''))
        {
            if(ch !== this.pattern[0])
            {
                return MATCH_FAILURE
            }
            else{
                this.pattern.splice(0,1)
                if(this.pattern.length === 0)
                {
                    return MATCH_SUCCESS
                }
            }
        }
        return MATCH_REMAIN
    }
}

const host = argv[2] || exit(1)
const portMap = new Map()

function clearConnection(port)
{
    portMap.delete(port)
}
function initConnection(port)
{
    portMap.set(port,new Matcher('SSH-'))
}
function readConnection(port,data)
{
    const matcher = portMap.get(port)
    try{
        const state = matcher.read(data)
    
    if(state == MATCH_FAILURE)
    {
        clearConnection(port)
        return true
    }
    else if(state == MATCH_SUCCESS)
    {
        clearConnection(port)
        console.log(`Port ${port} is an SSH port`)
        return true
    }
    else {
        return false
    }

    }
    catch(err)
    {
        console.log(`crash on port ${port}`)
    }
}

function scanPort(port)
{
    const sock = net.connect({
        host,
        port,
        timeout: CONNECTION_TIMEOUT
    })
    
    sock.on('error', ()=> {
        clearConnection(port)
        sock.end()
    })
    sock.on('close', ()=> {
        clearConnection(port)
        sock.end()
    })
    sock.on('end', ()=> {
        clearConnection(port)
        sock.end()
    })
    sock.on('timeout', ()=> {
        clearConnection(port);
        sock.destroy()
    })
    sock.on('connect',()=>{
        initConnection(port)
    })
    sock.on('data',(data)=>{
        if(readConnection(port,data.toString('ascii')))
        {
            sock.end()
        }
    })
}

let iter = portRange.from

let interval = setInterval(()=>{
    let step = SCANNING_STEP
    for(; iter <= portRange.to && step > 0 ; iter++, step--)
    {
        scanPort(iter)
    }
    console.log(`Scanned [${iter}/65535]`)
    if(iter == portRange.to)
    {
        clearInterval(interval)
    }
}, CONNECTION_TIMEOUT)
