"use strict";
/*

Hours of reverse engineering, finally working

© COPYRIGHT Tadeáš Souček - All Rights Reserved 
*/
const DEFAULT_PORT = 443;

const fs = require('fs');
const http = require('http');
const https = require('https');
const xmlp = require('xml2js');
const url = require('url');
const crypto = require('crypto');



function SHA256(input){
    return crypto.createHash('sha256').update(input).digest('hex');
}

function encryptPassword(password, inf){
    let s = inf.sessionID;
    let challenge = inf.challenge;
    let iter = parseInt(inf.iterations);
    let enc = SHA256(password) + challenge;
    for(let m = 1; iter > m; m++){
        enc = SHA256(enc);
    }
    return enc;
          
}

function numDig(num, digits){
    var str = Math.floor(num).toString();
    if(str.length > digits){
        str.length = digits;
        return str;
    }
    while(str.length < digits){
        str = `0${str}`;
    }
    return str;
}
function hkEncodeDate(d){
    if(typeof(date) !== "object"){
        d = new Date(d); //Convert timestamp to date
    }
    
    //endTime: 2022-07-04T23:59:59Z
    return `${numDig(d.getFullYear(), 4)}-${numDig(d.getMonth(), 2)}-${numDig(d.getDate(), 2)}T${numDig(d.getHours(), 2)}:${numDig(d.getMinutes(), 2)}:${numDig(d.getSeconds(), 2)}Z`;
}
function hkDecodeDate(hkdate){
    var sp = hkdate.split("T");
    var date = sp[0].split("-");
    var time = null;
    if(sp.length > 1){
        time = sp[1].split(":");
    }
    
    var d = new Date();
    d.setYear(date[0]);
    d.setMonth(date[1]);
    d.setDate(date[2]);
    d.setHours(time[0]);
    d.setMinutes(time[1]);
    d.setSeconds(time[2]);
    
    return d;
}

function dbglog(){
    //Comment out, if not debug
    console.log(...arguments);
}

class HikvisionClient{
    constructor(host, port, user, password){
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password;
        this.session = null;
        
        this.cookies = [];
    }
    getAuthHeaders(){
        var h = {
            Cookie: `language=en; WebSession=${this.session}`,
        };
        dbglog("Auth headers:", h);
        return h;
    }
    urlLoad(aUrl, postdata = null, additional_headers = {}){
        return new Promise(r => {
            var urlp = url.parse(aUrl);
            dbglog(`urlp.hostname: ${urlp.hostname}`)
    //         console.log(`urlp.path: ${urlp.path}`)
    //         console.log("urlp: ", urlp)
            const reqopts = {
                host: urlp.hostname,
                path: urlp.path,
                port: urlp.port || DEFAULT_PORT, 
                headers: {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0',
                    "Connection": "keep-alive",
                    ... additional_headers
                },
                method: (postdata) ? "POST" : "GET", 
    //             rejectUnauthorized: false
            }
            var module = ((urlp.protocol === "http:") ? http : https);
            dbglog(`Making ${(module == http) ? "HTTP" : "HTTPS"} request`);
            dbglog('reqopts: ', reqopts);
            let req = module.request(reqopts, (resp) => {
//                 console.log(`Status code: ${resp.statusCode}`)
                var str = "";
                resp.on('data', (chunk) => {
//                     console.log("RESPDATA");
                    str += chunk.toString();
                });
                resp.on('error', () => {
                    r(null);
                })
                resp.on('end', () => {
//                     console.log("RESPEND");
                    resp.headers["Set-Cookie"]
                    r(str);
                })
            });
            req.on('error', e => {
                dbglog("REQUEST ERROR: ", e);
                console.trace();
//                 throw e;
            })
            
//             console.log(`postData: ${postdata}`)
            if(postdata){
                req.end(postdata);
            }else{
                req.end();
            }
            /*console.log("REQ.end()");
            console.log("AFTER REQ.end()")*/;
            
        });
    }
    async login(protocol, opts = {}){
        if(!protocol){
            throw "ERROR: You must specify protocol as first arg";
        }
        this.protocol = protocol || "https:";
//         let baseurl_np = `${protocol}://${this.host}`;
//         let baseurl = `${baseurl_np}${this.port ? `:${this.port}` : ""}/`;

        let baseurl = `${protocol}://${this.host}${this.port ? `:${this.port}` : ""}/`;
        console.log(`baseurl: ${baseurl}`);
        this.baseurl = baseurl;
        
        dbglog(`Url: ${baseurl}/ISAPI/Security/sessionLogin/capabilities`)
        let xmlstr = await this.urlLoad(`${baseurl}/ISAPI/Security/sessionLogin/capabilities`);
//         fs.writeFileSync("/tmp/resptxt", xmlstr);
        let xml = await xmlp.parseStringPromise(xmlstr);
        dbglog('xml: ', xml);
        
        let inf = xml.SessionLoginCap;
        
        
        
        let encrypted = encryptPassword(this.password, {
            sessionID: inf.sessionID[0],
            challenge: inf.challenge[0],
            iterations: inf.iterations[0],
        })
        
        dbglog(`sessionID: ${inf.sessionID}`)
        this.session = inf.sessionID;
        let url = `${baseurl}/ISAPI/Security/sessionLogin?timeStamp=1656925838668`;
        const postdata = `
            <SessionLogin> 
                <userName>${this.user}</userName>
                <password>${encrypted}</password>
                <sessionID>${inf.sessionID}</sessionID>
            </SessionLogin>`;
        let resptxt = await this.urlLoad(url, postdata);
        dbglog("Loaded sessionLogin")
        
//         fs.writeFileSync("/tmp/resptxt", `sessionLoginResponse:\n${resptxt}`);
        let respxml = await xmlp.parseStringPromise(resptxt);
        dbglog("xml: ", respxml);
        
        respxml = respxml.SessionUserCheck;
        if(respxml.sessionID){
            this.session = respxml.sessionID[0];
        }
        if((respxml.statusValue[0] == 200) && (respxml.statusString == "OK")){
            if(opts.storeSession !== false){
                fs.writeFileSync(".hikvision_session", JSON.stringify({
                    user: this.user,
                    host: this.host,
                    sessionID: this.session,
                }));
            }
            return [true, respxml];
        }else{
            return [false, respxml];
        }
    }
    async getChannels(){
        var res = [];
        
        let str = this.urlLoad(`${baseurl}/ISAPI/ContentMgmt/InputProxy/channels?security=1&iv=114adf6025dc2125b2386dd1f1531d89`, null, this.getAuthHeaders());
        let xml = await xmlp.parseStringPromise(str);
        let lst = xml.InputProxyChannelList.InputProxyChannel;
        l = lst.length;
        res.length = l;
        for(let i = 0; i < l; i++){
            let channel = lst[i];
            res[i] = {
                id: channel.id,
                name: channel.name,
                sourceInputPorts: channel.sourceInputPortDescriptor,
            }
        }
    }
    async getFilesBetweenStr(trackID, startTimeStr, endTimeStr, maxResults = 0xffff){
        /*
        TESTING VALUES:
        trackID: 101
        startTime: 2022-07-02T00:00:00Z
        endTime: 2022-07-04T23:59:59Z
        */
        const postdata = `
        <?xml version="1.0" encoding="UTF-8"?>
        <CMSearchDescription>
            <searchID>C9E30924-D870-0001-CE34-118B1F691BCF</searchID>
            <trackList><trackID>${trackID}</trackID></trackList>
            <timeSpanList><timeSpan><startTime>${startTimeStr}</startTime><endTime>${endTimeStr}</endTime></timeSpan></timeSpanList><maxResults>${maxResults}</maxResults><searchResultPostion>0</searchResultPostion><metadataList><metadataDescriptor>//recordType.meta.std-cgi.com</metadataDescriptor></metadataList></CMSearchDescription>`;
            
        
        var str = await this.urlLoad(`${this.baseurl}/ISAPI/ContentMgmt/search`, postdata, this.getAuthHeaders());
        var xml = await xmlp.parseStringPromise(str);
        
        dbglog("Tracks xml: ", xml);
        let sres = xml.CMSearchResult; //Search result
        if((sres.responseStatus > 200) && (sres.responseStatus[0] !== 'true')){
            return false;
        }
        
        var res = [];
        console.log("sres:", sres);
        
        let matches = sres.matchList;
        if(matches){
            let found = matches[0].searchMatchItem;
            var l = found.length;
            for(var i = 0; i < l; i++){
                let itm = found[i];
                let timespan = itm.timeSpan[0];
                let msd = itm.mediaSegmentDescriptor[0];
                res.push({
                    trackID: itm.trackID,
                    playbackURI: msd.playbackURI,
                    
                    startTime: hkDecodeDate(timespan.startTime[0]),
                    endTime: hkDecodeDate(timespan.endTime[0]),
                    contentType: msd.contentType,
                    codecType: msd.codecType,
                    
                    getBasename(){
                        return this.playbackURI.split("/").splice(-1);
                    }
                });
            }
        }
        return res;
    }
    getFilesBetween(trackID, startTime, endTime){
        return this.getFilesBetweenStr(trackID, hkEncodeDate(startTime), hkEncodeDate(endTime));
    }
    getParallelDownloaderEntry(playbackURI){
//         const playbackURI = `rtsp://souckoviny.eu/Streaming/tracks/${fnam}` ;
        
        //fnam can be i.e.: ?starttime=2022-07-04 16:59:09Z&amp;endtime=2022-07-04 17:15:08Z&amp;name=00010001955000000&amp;size=725004392`
        
        const postdata = `
            <?xml version='1.0'?>
            <downloadRequest>
                <playbackURI>${playbackURI}</playbackURI>
            </downloadRequest>
        `;
        playbackURI = playbackURI.toString();
        let lbl = "";
        try{
            lbl = playbackURI.split("starttime=")[1].split("&")[0];
        }catch(e){
            lbl = `Some video segment ${e.toString()}`;
        }
        dbglog(`DOWNURL: ${this.baseurl}/ISAPI/ContentMgmt/download`);
        return {
//             <?xml version='1.0'?><downloadRequest><playbackURI>rtsp://80.92.250.143/Streaming/tracks/101?starttime=2022-07-04 04:33:44Z&amp;endtime=2022-07-04 04:57:27Z&amp;name=00010001864000000&amp;size=1065016104</playbackURI></downloadRequest>
            url: `${this.baseurl}/ISAPI/ContentMgmt/download`,
            postData: postdata,
            filename: `${lbl}.mp4`,
            pbar_lbl: lbl,
            headers: this.getAuthHeaders(),
            makeRequest: function(){
                var urlp = url.parse(this.url);
                var mod = (urlp.protocol.startsWith("https") ? https : http);
                let req = mod.request({host: urlp.hostname, path: urlp.path, port: urlp.port, headers: this.headers, method: (this.postData) ? "POST" : "GET", rejectUnauthorized: false});
//                 req.write(this.postData);
                return {
                    req: req,
                    do_end: true,
                    postData: this.postData,
                };
            }
        }
    }
    async getFilesBetween_pdl(trackID, startTime, endTime){
        var tracks = await this.getFilesBetween(trackID, startTime, endTime);
        dbglog(`tracks: `, tracks)
        if(!tracks){
            return false;
        }
        var res = [];
        var l = tracks.length;
        res.length = l;
        for(var i = 0; i < l; i++){
            res[i] = this.getParallelDownloaderEntry(tracks[i].playbackURI);
        }
        return res;
    }
    
} 

if(require.main === module) {
    (new HikvisionClient())
}else{
    module.exports = {
        HikvisionClient,
        encryptPassword,
    }
}
