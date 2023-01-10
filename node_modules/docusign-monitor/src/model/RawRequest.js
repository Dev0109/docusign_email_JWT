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
    root.DocusignMonitor.RawRequest = factory(root.DocusignMonitor.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The RawRequest model module.
   * @module model/RawRequest
   */

  /**
   * Constructs a new <code>RawRequest</code>.
   * @alias module:model/RawRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RawRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RawRequest} obj Optional instance to populate.
   * @return {module:model/RawRequest} The populated <code>RawRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('queryScope')) {
        obj['queryScope'] = ApiClient.convertToType(data['queryScope'], 'String');
      }
      if (data.hasOwnProperty('queryScopeId')) {
        obj['queryScopeId'] = ApiClient.convertToType(data['queryScopeId'], 'String');
      }
      if (data.hasOwnProperty('query')) {
        obj['query'] = ApiClient.convertToType(data['query'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {module:model/RawRequest.QueryScopeEnum} queryScope
   */
  exports.prototype['queryScope'] = undefined;
  /**
   * @member {String} queryScopeId
   */
  exports.prototype['queryScopeId'] = undefined;
  /**
   * @member {String} query
   */
  exports.prototype['query'] = undefined;


  /**
   * Allowed values for the <code>queryScope</code> property.
   * @enum {String}
   * @readonly
   */
  exports.QueryScopeEnum = {
    /**
     * value: "AccountId"
     * @const
     */
    accountId: "AccountId",

    /**
     * value: "OrganizationId"
     * @const
     */
    organizationId: "OrganizationId",

    /**
     * value: "None"
     * @const
     */
    none: "None"
  };


  return exports;
}));


