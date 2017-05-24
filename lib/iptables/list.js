var exec = require('../child_utils').exec;
var tables = require('./utils').tables;

var Chain = require('../models/Chain');
var Rule = require('../models/Rule');

var q = require('q');

module.exports = function (options, cb) {
  
    if (typeof arguments[0] != 'object') {
        throw new Error('Invalid arguments. Signature: (options, callback?)');
    };

    var cTable = (typeof options.table != 'undefined') ? options.table : tables.filter;
    var bTableFound = false;

    var ipt_cmd = (options.sudo) ? 'sudo ' : '';
    ipt_cmd += (options.ipv6) ? 'ip6tables' : 'iptables';

    var noResolve = (options.resolve) ? '' : '-n';
    
    // Multiple tables
    if(cTable && cTable === "all" && cb) {

        var cmd;
        // Array of resulting objects
        var aCommands = [];

        for(var table in tables) {

            cmd = [ipt_cmd, '-t', table, '-vL', noResolve];
            aCommands.push(executeCmd(cmd.join(' '), options, table));

        }

        q.all(aCommands).then(function(aResult){
            cb('',{ tables: aResult });
        });

    }
    else {
        
        // Only one table
        /*
        * Build cmd to execute.
        */
        var cmd = [ipt_cmd, '-t', cTable, '-vL', noResolve];

        /*
        * Execute command.
        */
        exec(cmd.join(' '), {queue: options.queue}, function (error, stdout, stderror) {
            if (error && cb) {
                var err = new Error(stderror.split('\n')[0]);
                err.cmd = cmd.join(' ');
                err.code = error.code;
                cb(err);
            }
            else if (cb) {
                cb('',parseOutput(stdout, cTable));
            }
        });
    }
}

function parseOutput(cmdOutput, cTable){

    var oRet = { table: cTable, chains: [] };

    if(cmdOutput){

        var nI = 0, nX = 0;
        var aLines = cmdOutput.split('\n');
        var markRuleExtract = false;
        var aResult = [];

        var oChain;
        var oRule;

        for(nI=0;nI < aLines.length; nI++){

            cLine = aLines[nI].replace(/\s+/g, " ");

            if(markRuleExtract){
                // Extracts the rules
                aRules = extractRules(aLines.slice(nI));
                markRuleExtract = false;
                for(nX = 0; nX < aRules.length; nX++){
                    oChain.addRule(new Rule(aRules[nX]));
                }
                nI += aRules.length;
            } 
            else {
                
                // First occurence of a Chain
                if(/^Chain/.test(cLine)){

                    // Extracts the chain name and policy
                    aResult = /^Chain\s(\w+)\s\(policy\s(\w+)\s(\w+)\spackets\,\s(\w+)\sbytes\)/g.exec(cLine);
                    if(aResult && aResult.length > 3){
                        oChain = new Chain();
                        oChain.name = aResult[1];       // Chain Name
                        oChain.policy = aResult[2];     // Chain Policy
                        oChain.packets = aResult[3];    // Chain total Packets
                        oChain.bytes = aResult[4];      // Chain total Bytes
                        oRet.chains.push(oChain);
                        oChain = oRet.chains[oRet.chains.length-1];
                    };
                };

                // Verify header for the rules
                if(/^\spkts\sbytes/g.test(cLine)){
                    // Mark next line for rules extraction
                    markRuleExtract = true;
                }

            };

        };
    }
    return oRet;
}

function extractRules(aLines){

    var nX = 0;
    var aResult = [],
        aTemp = [];
    var cLine = "";

    for(nX = 0; nX < aLines.length; nX++){
        cLine = aLines[nX].replace(/\s+/g, " ").replace(/^\s/g,'');
        if(/^Chain/.test(aLines[nX]) || !cLine ){
            // End of rules
            nX = aLines.length;
        } else {
            aTemp = cLine.split(' ');
            aResult.push(aTemp);
        };
    }

    return aResult;

}

function executeCmd(cmd, options, table){
    
    var deferred = q.defer();
    
    /*
    * Execute command.
    */
    exec(cmd, {queue: options.queue}, function (error, stdout, stderror) {
        if (error) {
            var err = new Error(stderror.split('\n')[0]);
            err.cmd = cmd;
            err.code = error.code;
            console.error(err);
            deferred.reject(err);
        }
        else {
            deferred.resolve(parseOutput(stdout, table));
        }
    });

    return deferred.promise;

}