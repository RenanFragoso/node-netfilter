'use strict';

var Rule = function(aRule){
    this.pkts = "";
    this.bytes = "";
    this.target = "";
    this.prot = "";
    this.opt = "";
    this.in = "";
    this.out = "";
    this.source = "";
    this.destination = "";
    this.options = "";

    if(aRule && (aRule instanceof Array) && aRule.length >= 9){
        this.fromArray(aRule);
    }

};

Rule.prototype.fromArray = function (aRule) {
    
    if(aRule && (aRule instanceof Array) && aRule.length >= 9){
        this.pkts = aRule[0];
        this.bytes = aRule[1];
        this.target = aRule[2];
        this.prot = aRule[3];
        this.opt = aRule[4];
        this.in = aRule[5]
        this.out = aRule[6]
        this.source = aRule[7];
        this.destination = aRule[8];
        
        // Re-creates the options if exists
        if(aRule.length > 9){
            var aOptions = aRule.slice(9);
            this.options = aOptions.join(' ');
        }
    }
};

module.exports = Rule;