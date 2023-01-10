/**
 * Monitor API
 * An API for an integrator to access the features of DocuSign Monitor
 *
 * OpenAPI spec version: v2.0
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/AggregateResultResult'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./AggregateResultResult'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignMonitor) {
      root.DocusignMonitor = {};
    }
    root.DocusignMonitor.AggregateResult = factory(root.DocusignMonitor.ApiClient, root.DocusignMonitor.AggregateResultResult);
  }
}(this, function(ApiClient, AggregateResultResult) {
  'use strict';


  /**
   * The AggregateResult model module.
   * @module model/AggregateResult
   */

  /**
   * Constructs a new <code>AggregateResult</code>.
   * @alias module:model/AggregateResult
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>AggregateResult</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AggregateResult} obj Optional instance to populate.
   * @return {module:model/AggregateResult} The populated <code>AggregateResult</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('result')) {
        obj['result'] = ApiClient.convertToType(data['result'], [AggregateResultResult]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/AggregateResultResult>} result
   */
  exports.prototype['result'] = undefined;



  return exports;
}));


