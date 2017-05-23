'use strict';

var Chain = function(){
    this.name = "";
    this.policy = "";
    this.packets = "";
    this.bytes = ""
    this.rules = [];
};

Chain.prototype.addRule = function (oRule) {
    if(oRule && (typeof oRule === "object")){
        this.rules.push(oRule);
    }
};

module.exports = Chain;