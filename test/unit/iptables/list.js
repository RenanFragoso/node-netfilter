var should = require('should');
var list = require('../../../lib/iptables').list;
var utils = require('../../../lib/iptables').utils;

module.exports = function () {
  describe('#list', function () {
    it('should be defined', function () {
      should.exist(list);
    });

    describe('when executing with valid options', function(){
      describe('without specifying "table" ', function () {
        it('should correctly use the "filter" table (like the default iptables command)', function (done) {
          list({}, function (error, oResponse) {
            if (error) {
              done(error);
              return;
            }
            if(oResponse && oResponse.table && oResponse.table === "filter") {
              done();
            }
            else {
              done('default table not "filter"');
            }
          });
        });
      });
      describe('specifying "all" as table parameter', function(){
        it('should list all tables available (using the utils.tables defined)',function(done){
          list({table: "all"}, function(error,oResponse){
            if (error) {
              done(error);
              return;
            }
            if(oResponse && oResponse.tables && oResponse.tables.length == Object.keys(utils.tables).length) {
              done();
            }
            else {
              done('not all tables are returned in the response');
            }
          });
        });
      });
    });
    describe('when executing with invalid options', function(){
      describe('when requesting invalid table', function(){
        it('should return an error', function(done){
          list({table:"notexistenttable"}, function(error,oResponse){
            error.should.not.be.null
            done();
          });
        });
      });
    });

  });
};