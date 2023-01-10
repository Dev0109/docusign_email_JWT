/**
 * DocuSign Monitor API - v2
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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignMonitor) {
      root.DocusignMonitor = {};
    }
    root.DocusignMonitor.Aggregation = factory(root.DocusignMonitor.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The Aggregation model module.
   * @module model/Aggregation
   */

  /**
   * Constructs a new <code>Aggregation</code>.
   * @alias module:model/Aggregation
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>Aggregation</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/Aggregation} obj Optional instance to populate.
   * @return {module:model/Aggregation} The populated <code>Aggregation</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('aggregationName')) {
        obj['aggregationName'] = ApiClient.convertToType(data['aggregationName'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} aggregationName
   */
  exports.prototype['aggregationName'] = undefined;



  return exports;
}));


