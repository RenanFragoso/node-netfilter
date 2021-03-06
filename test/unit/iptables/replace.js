var should = require('should');

var replace = require('../../../lib/iptables').replace;
var flush = require('../../../lib/iptables').flush;
var append = require('../../../lib/iptables').append;

module.exports = function () {
  describe('#replace', function () {
    it('should be defined', function () {
      should.exist(replace);
    });

    it('should throw an error when invoked without `options` argument', function () {
      replace.bind(null).should.throw();
    });

    describe('when executing with valid options', function () {
      beforeEach(function (done) {
        append({
          table         : 'filter',
          chain         : 'FORWARD',
          protocol      : 'tcp',
          source        : '!10.10.10.0/24',
          destination   : '11.11.11.0/24',
          matches       : {
            comment: {
              comment: '"Some comment."'
            }
          },
          jump          : 'AUDIT',
          target_options: {
            type: 'drop'
          }
        }, function (error) {
          if (error) {
            done(error);
            return;
          }
          done();
        });
      });

      // Resetting `iptables` state.
      afterEach(function (done) {
        flush(function (error) {
          if (error) {
            done(error);
            return;
          }
          done();
        });
      });

      describe('with the full options', function () {
        it('should correctly replace the rule', function (done) {
          replace({
            table         : 'filter',
            chain         : 'FORWARD',
            rulenum       : 1,
            protocol      : 'tcp',
            source        : '!10.10.10.0/24',
            destination   : '11.11.11.0/24',
            matches       : {
              comment: {
                comment: '"Some comment."'
              }
            },
            jump          : 'AUDIT',
            target_options: {
              type: 'drop'
            }
          }, function (error) {
            if (error) {
              done(error);
              return;
            }
            done();
          });
        });
      });

      describe('without specifying `table`', function () {
        it('should correctly add the replace chain', function (done) {
          replace({
            chain         : 'FORWARD',
            rulenum       : 1,
            protocol      : 'tcp',
            source        : '!10.10.10.0/24',
            destination   : '11.11.11.0/24',
            matches       : {
              comment: {
                comment: '"Some comment."'
              }
            },
            jump          : 'AUDIT',
            target_options: {
              type: 'drop'
            }
          }, function (error) {
            if (error) {
              done(error);
              return;
            }
            done();
          });
        });
      });
    });

    describe('when executing with invalid options', function () {
      describe('without specifying `chain`', function () {
        it('should throw an error', function (done) {
          replace({
            rulenum       : 1,
            protocol      : 'tcp',
            source        : '!10.10.10.0/24',
            destination   : '11.11.11.0/24',
            matches       : {
              comment: {
                comment: '"Some comment."'
              }
            },
            jump          : 'AUDIT',
            target_options: {
              type: 'drop'
            }
          }, function (error) {
            error.should.not.be.null;
            done();
          });
        });
      });
    });
  });
};