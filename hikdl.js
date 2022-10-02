#!/bin/node

const hk = require('hikvision_dl');
const tspd = require('../ParallelDownloader/tsparallel_dl.js');
const url = require('url');
const fs = require('fs');
const promisify = require('util').promisify;

function StrToDate(strdate){
    //WARNING: User-friendly, but not (NOOB||HACKER)-checking
    //Please do not pentest this function
    //User-friendly date string
//     d.replace(/ /gi, "");
    d = strdate.split(".");
    
    var r = new Date();
    console.log("d: ", d);
    r.setDate(d[0]);
    r.setMonth(d[1]);
    var sp = d[2].replace(/( )+/gi, " ").split(" ");
    r.setYear(sp[0]);
    if(sp.length > 1){
        var tsp = sp[1].split(":"); //Time split
        r.setHours(tsp[0]);
        r.setMinutes(tsp[1]);
        r.setSeconds(tsp[2] || 0);
    }
    return r;
}

let args = process.argv;
// if(args[0].split(/\\|\//).splice(-1) === 'node'){
//
// }
args.splice(0, 2);

console.log(`args.length: ${args.length}`)
if((args.length < 5) || (args[0] == "--help")){
    console.log(`Usage:
    hikdl "http://HOST:PORT" [login] [password] [from_date] [to_date] [output_dir]
        Date format: '1.7.2022  13:30'  (write your own)
    Example:
        hikdl https://tssoftware.eu:6000 admin password123 '5.12.2020    8:30' '6.12.2020  17:55' Videos/Camera

    `)
    process.exit(1);
}

console.log("args:", args);
let urlp = url.parse(args[0]);
console.log("urlp:", urlp);
client = new hk.HikvisionClient(urlp.hostname, urlp.port, args[1], args[2]);
// client = new hk.HikvisionClient("192.168.16.160", 81, "admin", "Next-9361");
client.login("http").then(async (result) => {
    success = result[0]
    if(success === false){
        console.log("ERROR: Cannot log-in - bad password or not compatible");
        process.exit(5);
    }
    console.log(`StrToDate("1.7.2022   13:30"): ${StrToDate("1.7.2022   13:30")}`)
    var pd = new tspd.ParallelDownloader();
    let fls = await client.getFilesBetween_pdl("101", StrToDate(args[3]), StrToDate(args[4]))
//     let fls = await client.getFilesBetween_pdl("101", StrToDate("1.7.2022   13:30"), StrToDate("1.7.2022   18:30"))
    console.log("fls: ", fls);
    try{
        await promisify(fs.mkdir)(args[5]);
    }catch(e){
        if(e.code !== 'EEXIST'){
            throw e;
        }
    }
    pd.addUrls(fls, {outputDirectory: args[5]});
    await pd.downloadCLI(4);
});

