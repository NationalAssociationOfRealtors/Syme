//#!/usr/bin/env node

"use strict";

//
// includes
//
var anon = require('anonymous_fingerprint');
var fs = require("fs");
var geolitecity = require("geolitecity");
var http = require('http');
var sqlite3 = require("sqlite3");
var url = require("url");
var useragent = require("useragent");

//
// configuration
//
var BYPASS_MODE = false;
var COOKIE_NAME = "__syme_mark";
var CRLF = "\r\n";
var ENABLE_REDIRECTION = false;
var ENABLE_TREND = false;
var FRONTDOOR_MODE = false;
//var GEOLITECITY_REPOSITORY = "/work/projects/maxmind/repository/geolitecity.db";
var GEOLITECITY_REPOSITORY = "/work/projects/maxmind/repository/geoip.db";
//var LISTENING_DOMAIN = "localhost";
//var LISTENING_DOMAIN = "192.168.2.59";
var LISTENING_DOMAIN = "cto.realtors.org";
var LISTENING_PORT = 8080;
var MINIFY_BROWSER_JAVASCRIPT = true;
var PAGE_CALLBACK_NAME = "fp";
var PAGE_ID_NAME = "syme";
var REPOSITORY = "./repository/syme.db";
var VERBOSE_MODE = false;
var WAKEUP_LATENCY = 50;
var WRITE_AHEAD_LOGGING = true;

//
// global variables
//
var RESOURCE_URL = "http://" + LISTENING_DOMAIN + ":" + LISTENING_PORT + "/";
useragent(true);

//
// ensure database exists 
//
fs.exists(REPOSITORY, function(exists) {
  if (exists) {
    startSyme();
  } else {
logError("Database does not exist, run syme_init.js first.");
  }
});

function startSyme() {
logError("Syme starting");
  http.createServer(function(request, response) {
    var aURL=url.parse(request.url);
    var agent;
    switch (aURL.pathname) {

      case "/":
//
// give back nothing to  a call to root 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"text/html"});
        response.end();
        break;

      case "/" + PAGE_CALLBACK_NAME + ".js":

        var startTime = (new Date()).getTime();

//
// calculate fingerprint with browser acessible information
//
        response.statusCode = 200;
        response.setHeader("Cache-Control", "private");
        response.setHeader("Content-Type","application/javascript");
        if (BYPASS_MODE) {
logError("Should not be getting call to process " + request.url);
        }
        var args=request.url.substring(request.url.indexOf("?")+2,request.url.length);
        var additions = new Array();
        var user_ip;
        var user_ip_error;
        var cookiesEnabled = "true";
        var vars = args.split("&");
//if (VERBOSE_MODE) {
//console.dir(vars);
//}        
//        for (var i = 0; i < vars.length; i++) {
        for (var i = vars.length; i--;) {

          var pair = vars[i].split("=");
          switch (pair[0]) {
            case "ck":
              cookiesEnabled = decodeURIComponent(pair[1]).trim();
              break;
            case "ip":
              user_ip = decodeURIComponent(pair[1]).trim()//;
              break;
            case "ipe":
              user_ip_error = decodeURIComponent(pair[1]).trim();
              break;
            case "ua":
              var rightside;
              try {
                rightside = decodeURIComponent(pair[1]);
              } catch (e) {
logError("Error decoding element " + pair[0] + " value: " +pair[1]); 
                rightside = pair[1];
              }
              agent = useragent.parse(request.headers['user-agent'], rightside);
              break;
            default: 
              var rightside;
              try {
                rightside = decodeURIComponent(pair[1]);
              } catch (e) {
logError("Error decoding element " + pair[0] + " value: " +pair[1]); 
                rightside = pair[1];
              }
              additions[decodeURIComponent(pair[0])] = rightside;
          }
        }
        var getClientIp = function() {
          var ipAddress;
          var forwardedIpsStr = request.headers["x-forwarded-for"]; 
          if (forwardedIpsStr) {
// 'x-forwarded-for' header may return multiple IP addresses in
// the format: "client IP, proxy 1 IP, proxy 2 IP" so take the
// the first one
            var forwardedIps = forwardedIpsStr.split(",");
            ipAddress = forwardedIps[0];
          }
          if (!ipAddress) {
// Ensure getting client IP address still works in
// development environment
             ipAddress = request.connection.remoteAddress;
          }
          return ipAddress;
        };

        if (agent == null) {
logError("Problem with information from the browser possibly from " + getClientIp());
console.dir(agent);
console.dir(additions);
console.log(request.headers['user-agent']);
          response.end();
        } else {
          var bypassEvent = false;

//
// stop obviously spoofed IP addresses
//
//          if (user_ip == "127.0.0.1") {
          if (user_ip_error != "no_error") {
logError("IP Address Error " + user_ip_error);
            if (user_ip) {
logError("IP Address (" + user_ip + ") was found");
            } else {
              user_ip = getClientIp();
logError("No IP Address was found, trying IP Address (" + user_ip + ")");
            }
//            if (ENABLE_REDIRECTION) {
//              response.write("alert('IP  is Blacklisted');" + "\r\n");
//              response.write("location.assign('" + RESOURCE_URL + "address.html');");
//            }
//            bypassEvent = true;
console.dir(agent);
console.dir(additions);
console.log(request.headers['user-agent']);
          }

//
// note users
//
          if (agent.family == "Slurp" ) {
//              var optionsx = {mode: "ASYNC", userIP: user_ip };
//            anon.basis(request, additions, optionsx, function(elements){
//console.dir(elements);
//            });
            bypassEvent = true;
logError("Bypass Slurp");
          }

          if (bypassEvent) {
            response.end();
          } else {
//
// dnt - Do Not Track 
//
            var dnt = "false";
            if (request.headers["dnt"] ) {
              if (request.headers["dnt"] == "1") {
                dnt = "true";
              }
            }
            additions["dt"] = dnt;
            additions["ck"] = cookiesEnabled;

//
// generate fingerprint
//
            var fingerprintOptions = {cookieName: COOKIE_NAME, mode: "ASYNC", userIP: user_ip };
            if (FRONTDOOR_MODE || cookiesEnabled == "false" || dnt == "true") {
              fingerprintOptions = {mode: "ASYNC", userIP: user_ip };
            }
            anon.fingerprint(request, additions, fingerprintOptions, function(tags){
              var requestTimestamp = new Date();
              var hostName = "DIRECT";
              var hostHref = "Unknown";
              if (request.headers["referer"] ) {
                hostName = url.parse(request.headers["referer"]).hostname;
                hostHref = url.parse(request.headers["referer"]).href;
              }
              var db = new sqlite3.Database(REPOSITORY);
              db.serialize( function() {


//
// turn on Write Ahead Logging
//
                if (WRITE_AHEAD_LOGGING) {
                  db.exec("PRAGMA journal_mode=WAL");
                }

                var checkReferer = function(callback) {
                  var stmt = "SELECT blacklisted FROM referer WHERE host='" + hostName + "'";
                  db.all(stmt, function(err, rows) {
                    if (err) {
console.log("checkReferer error detected", err);
                    }
                    if (!rows) {
logError("Syme DB Locked for checkReferer, retrying ...");
                    } else {
                      var blacklisted = false;
                      var known = false;
                      if (rows.length != 0) {
                        rows.forEach(function (row) {
                          if (row.blacklisted == 1 ) {
                            blacklisted = true;
                          } else {
                            known = true;
                          }
                        });
                      }
                      callback({blacklisted:blacklisted,known:known});
                    }
                  });
                }
                checkReferer(function(referer) {
                  if (referer.blacklisted) {
console.log("Host " + hostName + " has been Blacklisted");
                    if (ENABLE_REDIRECTION) {
                      response.write("alert('Referer is Blacklisted');" + "\r\n");
                      response.write("location.assign('" + RESOURCE_URL + "referer.html');");
                    }
                    db.close();
                  } else {
//=============
try{
                    if (!referer.known) {
                      if (ENABLE_REDIRECTION) {
console.log("Blacklist the new host " + hostName);
                        db.prepare("INSERT INTO referer(host,blacklisted) VALUES(?,?)").run(hostName,1).finalize(); 
                        response.write("alert('New host has been Blacklisted');" + "\r\n");
                        response.write("location.assign('" + RESOURCE_URL + "referer.html');");
                      } else {
logError("Whitelist the new host " + hostName);
                        db.prepare("INSERT INTO referer(host,blacklisted) VALUES(?,?)").run(hostName,0).finalize(); 
                      }
                    }

                    var checkFingerprint = function(callback) {
                      var stmt = "SELECT blacklisted FROM fingerprint WHERE hash='" + tags.uid + "'";
                      db.all(stmt, function(err, rows) {
                        if (err) {
console.log("checkFingerprint error detected", err);
                        }
                        if (!rows) {
logError("Syme DB Locked for checkFingerprint, retrying ...");
                        } else {
                          var blacklisted = false;
                          var known = false;
                          if (rows.length != 0) {
                            rows.forEach(function (row) {
                              if (row.blacklisted == 1 ) {
                                blacklisted = true;
                              } else {
                                known = true;
                              }
                            });
                          }       
                          callback({blacklisted:blacklisted,known:known});
                        }
                      });
                    }
                    checkFingerprint(function(fingerprint) {
                      if (fingerprint.blacklisted) {
console.log("Fingerprint " + tags.uid + " has been Blacklisted");
                        if (ENABLE_REDIRECTION) {
                          response.write("alert('Fingerprint is Blacklisted');" + "\r\n");
                          response.write("location.assign('" + RESOURCE_URL + "fingerprint.html');");
                        }
                        response.end();
                        db.close();
                      } else {
//
// add fingerprint as a cookie
//
                        if (!FRONTDOOR_MODE) {
                          var expirationDate = new Date();
                          var years=10;
                          expirationDate.setTime(expirationDate.getTime()+(years*365*24*60*60*1000));
                          response.setHeader("Set-Cookie", COOKIE_NAME + "=" + tags.uid + "; expires=" + expirationDate.toGMTString() + "; path=/");
                        }
                        response.end();
//
// process collected information
//
                        var lookupOptions = {repository: GEOLITECITY_REPOSITORY, userIP: user_ip, verbosr: false };
                        geolitecity.lookupIP(lookupOptions,function(ipOutput){

                        var requestCell = (Math.floor(requestTimestamp.getDay() * 24) + (requestTimestamp.getHours() + 1));

//
// process usage trend
//
                          if (ENABLE_TREND) {

//
// reset "symePoints" horizon 
//
                            var stmt = "DELETE FROM trend WHERE cell > " + requestCell;
                            var clearBack = requestCell - Math.floor(5 * 24); 
                            if (clearBack != 0) {
                              if (clearBack < 0) {
                                stmt += " AND cell < " + Math.abs(168+clearBack+1);
                              } else {
                                stmt += " AND cell < " + (clearBack+1);
                              }
                            }
                            db.exec(stmt);

//
// determine "symePoints" 
//
// prerender / prefetch
// Firefox X-moz: prefetch
// Safari X-Purpose: preview
// Chrome none 
                            var keyDirectories = "directories";
                            var unmappedCountry = new Array();
                            unmappedCountry.push("AU"); 
                            unmappedCountry.push("BE"); 
                            unmappedCountry.push("BR"); 
                            unmappedCountry.push("CA"); 
                            unmappedCountry.push("DE"); 
                            unmappedCountry.push("DK"); 
                            unmappedCountry.push("ES"); 
                            unmappedCountry.push("FI"); 
                            unmappedCountry.push("FR"); 
                            unmappedCountry.push("GB"); 
                            unmappedCountry.push("IL"); 
                            unmappedCountry.push("IT"); 
                            unmappedCountry.push("JP"); 
                            unmappedCountry.push("NL"); 
                            unmappedCountry.push("NZ"); 
                            unmappedCountry.push("PT"); 
                            unmappedCountry.push("SE"); 
                            unmappedCountry.push("US"); 
                            unmappedCountry.push("ZA"); 
                            var symePoints = 0;
                            var symeMessage = "";

                            if (hostHref.indexOf(keyDirectories) > -1) {
symeMessage += CRLF + "** (7) Access to key directory";
                              symePoints += 7;
                            }
                            if (dnt == "true") {
symeMessage += CRLF + "** (1) Do Not Track requested";
                              symePoints += 1;
                            }
                            if (cookiesEnabled == "false") {
symeMessage += CRLF + "** (1) Cookies disabled";
                              symePoints += 1;
                            }
                            var offsetFromBrowser = Math.floor(additions["tz"]/60);
                            if (unmappedCountry.indexOf(ipOutput.country_code) > -1) {
symeMessage += CRLF + "** (-3) Country IP structure not fully mapped " + ipOutput.country_code;
                              symePoints -= 3;
                            }
                            if (ipOutput.error) {
                              if (offsetFromBrowser < -1) {
symeMessage += CRLF + "** (3) Browser is east of Europe " + ipOutput.country_code;
                                symePoints += 3;
                              }
symeMessage += CRLF + "** (2) Time zone for address: " + user_ip + " cannot be determined but a browser timezone of " + offsetFromBrowser + " was detected";
                              symePoints += 2;
                            } else {
                              if ((ipOutput.tz_offset != offsetFromBrowser)) {
symeMessage += CRLF + "** (1) Detected a browser timezone of " + offsetFromBrowser + " and a connection timezone of " + ipOutput.tz_offset;
                                symePoints += 1;
                                if (ipOutput.tz_offset > offsetFromBrowser) {
symeMessage += CRLF + "** (1) Browser is further east than the connection implies";
                                  symePoints += 1;
                                  var diff = Math.abs(offsetFromBrowser - ipOutput.tz_offset);
                                  if (diff > 4) {
symeMessage += CRLF + "** (2) Difference between browser and a connection timezones is greater than 4";
                                    symePoints += 2;
                                  }
                                }
                              }
                            }
                            if (symePoints > 5) {
                              var captureTrand = function() {
                                var stmt = "SELECT usage FROM trend WHERE browserName='" + agent.family + "' AND browserVersion='" + agent.toVersion() + "' AND cell=" + requestCell + " AND city='" + ipOutput.city + "' AND countrycode='" + ipOutput.country_code + "' AND deviceName='" + agent.device.family + "' AND operatingSystem='" + agent.os.family + "' AND operatingSystemVersion='" + agent.os.toVersion() + "'";
                                db.all(stmt, function(err, rows) {
                                  if (!rows) {
                                      stmt = db.prepare("INSERT INTO trend(browserName,browserVersion,cell,city,countrycode,deviceName,operatingSystem,operatingSystemVersion,usage) VALUES(?,?,?,?,?,?,?,?,1)");
                                      stmt.run(agent.family,agent.toVersion(),requestCell,ipOutput.city,ipOutput.country_code,agent.device.family,agent.os.family,agent.os.toVersion()).finalize(); 
                                  } else {
                                    if (rows.length != 0) {
                                      rows.forEach(function (row) {
                                        stmt = db.prepare("UPDATE trend SET usage=? WHERE browserName=? AND browserVersion=? AND cell=? AND city=? AND countrycode=? AND deviceName=? AND operatingSystem=? AND operatingSystemVersion=?");
                                        stmt.run((row.usage + 1),agent.family,agent.toVersion(),requestCell,ipOutput.city,ipOutput.country_code,agent.device.family,agent.os.family,agent.os.toVersion()).finalize(); 
                                      });
                                    } else {
logError("Syme DB captureTrend should not be here ...");
                                      stmt = db.prepare("INSERT INTO trend(browserName,browserVersion,cell,city,countrycode,deviceName,operatingSystem,operatingSystemVersion,usage) VALUES(?,?,?,?,?,?,?,?,1)");
                                      stmt.run(agent.family,agent.toVersion(),requestCell,ipOutput.city,ipOutput.country_code,agent.device.family,agent.os.family,agent.os.toVersion()).finalize(); 
                                    }
                                  }
                                });
                              }
                              captureTrend();

                              var checkSymePoints = function(callback) {
                                var stmt = "SELECT cell,usage FROM trend WHERE browserName='" + agent.family + "' AND browserVersion='" + agent.toVersion() + "' AND city='" + ipOutput.city + "' AND countrycode='" + ipOutput.country_code + "' AND deviceName='" + agent.device.family + "' AND operatingSystem='" + agent.os.family + "' AND operatingSystemVersion='" + agent.os.toVersion() + "'";
                                db.all(stmt, function(err, rows) {
                                  if (!rows) {
                                  } else {
                                    var singleCell = 1;
                                    var totalCells = 1;
                                    if (rows.length != 0) {
                                      rows.forEach(function (row) {
                                        totalCells += row.usage;
                                        if (row.cell == requestCell) {
                                          singleCell += row.usage;
                                        } 
                                      });
                                    }
                                    callback({singleCell:singleCell,totalCells:totalCells});
                                  }
                                });
                              }
                              checkSymePoints(pOutput,function(points) {
logError(requestTimestamp +
         CRLF + "** Syme Sez: " + symePoints + symeMessage + 
         CRLF + "** Referer: " + hostName + 
         CRLF + "** Device: " + agent.family + " on " + agent.os.family + " (" + agent.os.toVersion() + ")" +
         CRLF + "** Location: " + ipOutput.city + " " + ipOutput.country_code +
         CRLF + "** Href: " + hostHref + 
         CRLF + "** Usage within this cell " + points.singleCell + 
         CRLF + "** Usage within all cells " + points.totalCells);
                              });
                            }
                          }

//
// location hash
//
                          var elements = [
                            ipOutput.areacode.toString(),
                            user_ip,
                            ipOutput.metrocode.toString(),
                            ipOutput.city,
                            ipOutput.region_code,
                            ipOutput.country_code,
                            ipOutput.zipcode
                          ];
                          var locationHash = anon.calculateHash(elements);

                          var checkLocation = function(callback) {
if (VERBOSE_MODE) {
console.log("---------> checkLocation");
}
                            var stmt = "SELECT usage FROM location WHERE hash='" + locationHash + "'";
                            db.all(stmt, function(err, rows) {
                              if (err) {
console.log("checkLocation error detected", err);
                              }
                              if (!rows) {
logError("Syme DB Locked for checkLocation, retrying ...");
                              } else {
                                var known = false;
                                var usage = 0;
                                if (rows.length != 0) {
                                  rows.forEach(function (row) {
                                    known = true;
                                    usage = row.usage;
                                  });
                                }
                                try {
                                  callback({known:known,usage:usage});
                                } catch (err) {
consoleTrace("checkLocation " + err);
                                }
                              }
                            });
                          }

                          var checkDevice = function(callback) {
                            var stmt = "SELECT usage FROM device WHERE hash='" + tags.fingerprint + "'";
                            db.all(stmt, function(err, rows) {
                              if (err) {
console.log("checkDevice error detected", err);
                              }
                              if (!rows) {
logError("Syme DB Locked for checkDevice, retrying ...");
                              } else {
                                var known = false;
                                var usage = 0;
                                if (rows.length != 0) {
                                  rows.forEach(function (row) {
                                    known = true;
                                    usage = row.usage;
                                  });
                                }
                                try{
                                  callback({known:known,usage:usage});
                                } catch (err) {
console.trace("checkDevice " + err);
                                }
                              }
                            });
                          }

                          var executeFlow = function(stack) {
                            if (stack.length > 0) {
                              var args = stack.shift();
                              var func = args[0];
                              args.shift();
if (VERBOSE_MODE) {
console.log("---------> " + func.name);
}
                              try {
                                func(stack,args);
                              } catch (err) {
console.trace("executeFlow " + err);
//      setTimeout(func,WAKEUP_LATENCY,db,stack,startTime,args);
                              }
                            }
                          }

//
// Atomic Operations
//

var incrementFingerprint = function incrementFingerprint(stack,arg) {
  var hash = arg[0];
  var stmt = db.prepare("UPDATE fingerprint SET timestamp=? WHERE hash=?");
  stmt.run(requestTimestamp,hash);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var closeSymeDatabase = function closeSymeDatabase(stack) {
  db.close();
if (VERBOSE_MODE) {
  var endTime = (new Date()).getTime();
  if (endTime < startTime) {
console.log(endTime + " " + startTime);
console.log("Execution Time: 0 ms ??");
  } else {
console.log("Execution Time: " + (endTime - startTime) + "ms");
  }
}
}

var incrementFingerprintWithDevice = function incrementFingerprintWithDevice(stack, arg) {
  var stmt = db.prepare("UPDATE fingerprint SET timestamp=? WHERE device=?");
  stmt.run(requestTimestamp,tags.fingerprint);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var captureResource = function captureResource(stack, arg) {
  var uid = arg[0];
  var stmt = "SELECT usage FROM content WHERE hash='" + uid + "' AND page=" + hostHref;
  db.all(stmt, function(err, rows) {
    if (!rows) {
      var stmt = db.prepare("INSERT INTO content(hash,location,timestamp,page,usage) VALUES(?,?,?,?,?)");
      stmt.run(uid,locationHash,requestTimestamp,hostHref,1);
      stmt.finalize(function() {
        executeFlow(stack);
      }); 
    } else {
      if (rows.length != 0) {
        rows.forEach(function (row) {
          var stmt = db.prepare("UPDATE content SET usage=?,location=?,timestamp=? WHERE hash=? AND page=?");
          stmt.run((row.usage + 1),locationHash,requestTimestamp,uid,hostHref);
          stmt.finalize(function() {
            executeFlow(stack);
          });
        });
      } else {
logError("Syme DB captureResource should not be here ...");
        var stmt = db.prepare("INSERT INTO content(hash,location,timestamp,page,usage) VALUES(?,?,?,?,?)");
        stmt.run(uid,locationHash,requestTimestamp,hostHref,1);
        stmt.finalize(function() {
          executeFlow(stack);
        }); 
      }
    }
  });
}

var captureTOD = function captureTOD(stack, arg) {
  var uid = arg[0];
  var stmt = "SELECT usage FROM tod WHERE hash='" + uid + "' AND cell=" + requestCell;
  db.all(stmt, function(err, rows) {
    if (!rows) {
//throw new Error("Syme DB Locked for captureTOD, retrying ...");
logError("Syme DB captureTOD should not be here ...");
        var stmt = db.prepare("INSERT INTO tod(hash,location,timestamp,cell,usage) VALUES(?,?,?,?,?)");
        stmt.run(uid,locationHash,requestTimestamp,requestCell,1);
        stmt.finalize(function() {
          executeFlow(stack);
        }); 
    } else {
      if (rows.length != 0) {
        rows.forEach(function (row) {
          var stmt = db.prepare("UPDATE tod SET usage=?,location=?,timestamp=? WHERE hash=? AND cell=?");
          stmt.run((row.usage + 1),locationHash,requestTimestamp,uid,requestCell);
          stmt.finalize(function() {
            executeFlow(stack);
          });
        });
      } else {
        var stmt = db.prepare("INSERT INTO tod(hash,location,timestamp,cell,usage) VALUES(?,?,?,?,?)");
        stmt.run(uid,locationHash,requestTimestamp,requestCell,1);
        stmt.finalize(function() {
          executeFlow(stack);
        }); 
      }
    }
  });
}

var captureFingerprintLocation = function captureFingerprintLocation(stack, arg) {
  var stmt = db.prepare("INSERT INTO fingerprintLocation(hash,location,timestamp,usage) VALUES(?,?,?,?)");
  stmt.run(tags.uid,locationHash,requestTimestamp,1);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var captureFingerprint = function captureFingerprint(stack, arg) {
  var stmt = db.prepare("INSERT INTO fingerprint(hash,device,timestamp,blacklisted) VALUES(?,?,?,?)");
  stmt.run(tags.uid,tags.fingerprint,requestTimestamp,0);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var captureDevice = function captureDevice(stack, arg) {
  var geoLocation = (additions["gl"] == "true")? 1:0; 
  var localStorage = (additions["ls"] == "true")? 1:0; 
  var sessionStorage = (additions["ss"] == "true")? 1:0; 
  var webSockets = (additions["ws"] == "true")? 1:0; 
  var cookies = (additions["ck"] == "true")? 1:0;
  var doNotTrack = (additions["dt"] == "true")? 1:0; 
  var stmt = db.prepare("INSERT INTO device(hash,timestamp,browserName,browserVersion,operatingSystem,operatingSystemVersion,deviceName,geolocation,localStorage,screenDepth,screenHeight,screenWidth,doNotTrack,sessionStorage,webSockets,cookies,usage) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  stmt.run(tags.fingerprint,requestTimestamp,agent.family,agent.toVersion(),agent.os.family,agent.os.toVersion(),agent.device.family,geoLocation,localStorage,additions["sd"],additions["sh"],additions["sw"],doNotTrack,sessionStorage,webSockets,cookies,1);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var incrementDevice = function incrementDevice(stack, arg) {
  var usage = arg[0];
  var stmt = db.prepare("UPDATE device SET usage=?,timestamp=? WHERE hash=?");
  stmt.run(usage,requestTimestamp,tags.fingerprint);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var captureLocation = function captureLocation(stack, arg) {
  var stmt = db.prepare("INSERT INTO location(hash,timestamp,areacode,ipAddress,metrocode,city,regioncode,countrycode,zipcode,usage) VALUES(?,?,?,?,?,?,?,?,?,?)");
  stmt.run(locationHash,requestTimestamp,ipOutput.areacode,user_ip,ipOutput.metrocode,ipOutput.city,ipOutput.region_code,ipOutput.country_code,ipOutput.zipcode,1);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var incrementLocationRecord = function incrementLocationRecord(stack, arg) {
  var usage = arg[0];
  var stmt = db.prepare("UPDATE location SET usage=?,timestamp=? WHERE hash=?"); 
  stmt.run(usage,requestTimestamp,locationHash);
  stmt.finalize(function () {
    executeFlow(stack);
  }); 
}

var incrementFingerprintLocation = function incrementFingerprintLocation(stack, arg) {
  var hash = arg[0];
  var stmt = "SELECT usage FROM fingerprintLocation WHERE hash='" + hash + "' AND location='" + locationHash + "'";
  db.all(stmt, function(err, rows) {
    if (!rows) {
throw new Error("Syme DB Locked for incrementFingerprintLocation, retrying ...");
    } else {
      if (rows.length != 0) {
        rows.forEach(function (row) {
          var stmt = db.prepare("UPDATE fingerprintLocation SET usage=?,timestamp=? WHERE hash=? and location=?");
          stmt.run((row.usage + 1),requestTimestamp,hash,locationHash);
          stmt.finalize(function () {
            executeFlow(stack);
          }); 
        });
      }
    }
  });
}
                          var stack = new Array();
                          var useTrackingCookie = "true";
                          if (cookiesEnabled == "false" || dnt == "true") {
                            useTrackingCookie = "false";
                          }
                          if (useTrackingCookie == "true") {
                            checkDevice(function(device) {
                              if (device.known) {
                                stack.push([incrementDevice,(device.usage+1)]);
                                checkLocation(function(location) {
                                  if (location.known) {
                                    stack.push([incrementLocationRecord,(location.usage+1)]);
                                    stack.push([incrementFingerprintLocation,tags.uid]);
                                  } else {
//console.log("- Known Device , new Location");
                                    stack.push([captureLocation]);
                                    stack.push([captureFingerprintLocation]);
                                  }
                                  stack.push([incrementFingerprintWithDevice]);
                                  stack.push([captureTOD,tags.uid]);
                                  stack.push([captureResource,tags.uid]);
                                  stack.push([closeSymeDatabase]);
                                  executeFlow(stack);
                                });
                              } else {
//console.log("- New Device");
                                stack.push([captureDevice]);
                                checkLocation(function(location) {
                                  if (location.known) {
                                    stack.push([incrementLocationRecord,(location.usage+1)]);
                                  } else {
//console.log("- New Location");
                                    stack.push([captureLocation]);
                                  }
                                  stack.push([captureFingerprintLocation]);
                                  stack.push([captureFingerprint]);
                                  stack.push([captureTOD,tags.uid]);
                                  stack.push([captureResource,tags.uid]);
                                  stack.push([closeSymeDatabase]);
                                  executeFlow(stack);
                                });
                              }
                            }); // checkDevice
                          } else {
//console.log("- Device has cookies off or requested to not be tracked");

                            var findFingerprint = function(callback) {
                              var stmt = "SELECT usage,hash FROM device WHERE hash='" + tags.fingerprint + "'";
                              var found = false; 
                              db.all(stmt, function(err, rows) {
                                if (err) {
console.log("findFingerprint error detected", err);
                                }
                                if (!rows) {
logError("Syme DB Locked for findFingerprint routine , retrying ...");
                                } else {
                                  if (rows.length != 0) {
                                    rows.forEach(function (row) {
                                      stmt = "SELECT location.usage,fingerprint.hash FROM location,fingerprintLocation,fingerprint WHERE location.hash=fingerprintLocation.location AND fingerprint.hash=fingerprintLocation.hash AND location.hash='"+locationHash + "' AND fingerprint.device='" + row.hash + "'";
                                      db.all(stmt, function(err, rows2) {
                                        if (err) {
console.log("findFingerprint deep error detected", err);
                                        }
                                        if (!rows) {
logError("Syme DB Locked for deep findFingerprint routine , retrying ...");
                                        } else {
                                          if (rows2.length != 0) {
                                            rows2.forEach(function (row2) {
                                              if (!found) {
                                                found = true;
                                                callback({known:true,deviceUsage:row.usage,hash:row2.hash,locationUsage:row2.usage});
                                              }
                                            });
                                          } else {
                                            callback({deviceKnown:false,deviceUsage:0,hash:null,locationUsage:0});
                                          }
                                        }
                                      });
                                    });
                                  } else {
                                    callback({deviceKnown:false,deviceUsage:0,hash:null,locationUsage:0});
                                  }
                                }
                              });
                            }
                            findFingerprint(function(fingerprint2) {
                              if (fingerprint2.known) {
                                stack.push([incrementDevice,(fingerprint2.deviceUsage+1)]);
                                stack.push([incrementLocationRecord,(fingerprint2.locationUsage+1)]);
                                stack.push([incrementFingerprintLocation,fingerprint2.hash]);
                                stack.push([incrementFingerprint,fingerprint2.hash]);
                                stack.push([captureTOD,fingerprint2.hash]);
                                stack.push([captureResource,fingerprint2.hash]);
                                stack.push([closeSymeDatabase]);
                                executeFlow(stack);
                              } else {
//console.log("- Creating Fingerprint");
                                checkDevice(function(device) {
                                  if (device.known) {
                                    stack.push([incrementDevice,(device.usage+1)]);
                                  } else {
                                    stack.push([captureDevice]);
                                  }
                                  checkLocation(function(location) {
                                    if (location.known) {
//console.log("- Known Location");
                                      stack.push([incrementLocationRecord,(location.usage+1)]);
                                    } else {
                                      stack.push([captureLocation]);
                                    }
                                    stack.push([captureFingerprintLocation]);
                                    stack.push([captureFingerprint]);
                                    stack.push([captureTOD,tags.uid]);
                                    stack.push([captureResource,tags.uid]);
                                    stack.push([closeSymeDatabase]);
                                    executeFlow(stack);
                                  });
                                });
                              }
                            }); // findFingerprint
                          }
                        }); // geocitylight.lookupIP()
                      }  // fingerprint not blacklisted
                    }); // checkFingerprint
} catch (err) {
console.trace("checkReferer " + err);
}
//===========
                  }  // referer not blacklisted
                }); // checkReferer
              }); // db serialize
//console.log(requestTimestamp + " - Request from " + user_ip + ", device -> " + tags.fingerprint);
if (VERBOSE_MODE) {
  var responseTime = (new Date()).getTime();
console.log("Response Time: " + (responseTime - startTime) + "ms");
}
            }); // fingerprinting
          } // capture event
        } // ip address is not null
        break;

      case "/" + PAGE_ID_NAME + ".js":
//
// return javascript to gather browser accessible information to report back
//
        if (BYPASS_MODE) {
            response.writeHead(200, {"Cache-Control":"private","Content-Type":"application/javascript"});
            response.end();
        } else {
//console.log(request.method);
//console.dir(request.headers);
          response.writeHead(200, {
"Expires": "Sat, 1 Jan 2005 00:00:00 GMT",
"Last-Modified": (new Date()),
"Cache-Control":"no-cache, must-revalidate",
"Pragma":"no-cache",
"Content-Type":"application/javascript"
});
          var scriptName = "api-min.js";
          if (FRONTDOOR_MODE) {
            response.write("var idName='" + PAGE_ID_NAME + "';");
            scriptName = "frontDoor-min.js";
            if (!MINIFY_BROWSER_JAVASCRIPT) {
              scriptName = "frontDoor.js";
            }
          } else {
            if (!MINIFY_BROWSER_JAVASCRIPT) {
              scriptName = "api.js";
            }
          }
          response.write("'use strict';");
          response.write("var callbackName='" + RESOURCE_URL+PAGE_CALLBACK_NAME + ".js';");
          fs.readFile("./resources/" + scriptName, "utf8", function (err, data) {
            if (err) throw err;
            response.write(data);
            response.end();
          });
        }
        break;

      case "/address.html":
//
// generate trap page 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"text/html"});
        fs.readFile("./resources/addressTrap.html", "utf8", function (err, data) {
          if (err) throw err;
          response.write(data);
          response.end();
        });
        break;

      case "/fingerprint.html":
//
// generate trap page 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"text/html"});
        fs.readFile("./resources/fingerprintTrap.html", "utf8", function (err, data) {
          if (err) throw err;
          response.write(data);
          response.end();
        });
        break;

      case "/referer.html":
//
// generate trap page 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"text/html"});
        fs.readFile("./resources/refererTrap.html", "utf8", function (err, data) {
          if (err) throw err;
          response.write(data);
          response.end();
        });
        break;

      case "/robots.txt":
//
// give back nothing to robots.txt 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"text/html"});
        response.end();
        break;

      default: 
//
// unexpected calls 
//
        response.writeHead(200, {"Cache-Control":"private","Content-Type":"application/javascript"});
        response.end();
logError("Should not be getting call to " + request.url);

    } // default processing
  }).listen(LISTENING_PORT, LISTENING_DOMAIN);
}

//
// callback operations
//

function logError(errorText) {
console.log("**********************************************************************");
console.log("** " + new Date() + " " + errorText);
console.log("**********************************************************************");
}

