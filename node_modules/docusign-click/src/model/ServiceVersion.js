/**
 * DocuSign Click API
 * DocuSign Click lets you capture consent to standard agreement terms with a single click: terms and conditions, terms of service, terms of use, privacy policies, and more. The Click API lets you include this customizable clickwrap solution in your DocuSign integrations.
 *
 * OpenAPI spec version: v1
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
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.ServiceVersion = factory(root.DocusignClick.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ServiceVersion model module.
   * @module model/ServiceVersion
   */

  /**
   * Constructs a new <code>ServiceVersion</code>.
   * @alias module:model/ServiceVersion
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ServiceVersion</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ServiceVersion} obj Optional instance to populate.
   * @return {module:model/ServiceVersion} The populated <code>ServiceVersion</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('version')) {
        obj['version'] = ApiClient.convertToType(data['version'], 'String');
      }
      if (data.hasOwnProperty('versionUrl')) {
        obj['versionUrl'] = ApiClient.convertToType(data['versionUrl'], 'String');
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} version
   */
  exports.prototype['version'] = undefined;
  /**
   * 
   * @member {String} versionUrl
   */
  exports.prototype['versionUrl'] = undefined;



  return exports;
}));


