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
    define(['ApiClient', 'model/ClickwrapVersion'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ClickwrapVersion'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.ClickwrapVersionsPagedResponse = factory(root.DocusignClick.ApiClient, root.DocusignClick.ClickwrapVersion);
  }
}(this, function(ApiClient, ClickwrapVersion) {
  'use strict';


  /**
   * The ClickwrapVersionsPagedResponse model module.
   * @module model/ClickwrapVersionsPagedResponse
   */

  /**
   * Constructs a new <code>ClickwrapVersionsPagedResponse</code>.
   * @alias module:model/ClickwrapVersionsPagedResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapVersionsPagedResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapVersionsPagedResponse} obj Optional instance to populate.
   * @return {module:model/ClickwrapVersionsPagedResponse} The populated <code>ClickwrapVersionsPagedResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('accountId')) {
        obj['accountId'] = ApiClient.convertToType(data['accountId'], 'String');
      }
      if (data.hasOwnProperty('clickwrapId')) {
        obj['clickwrapId'] = ApiClient.convertToType(data['clickwrapId'], 'String');
      }
      if (data.hasOwnProperty('clickwrapName')) {
        obj['clickwrapName'] = ApiClient.convertToType(data['clickwrapName'], 'String');
      }
      if (data.hasOwnProperty('minimumPagesRemaining')) {
        obj['minimumPagesRemaining'] = ApiClient.convertToType(data['minimumPagesRemaining'], 'Number');
      }
      if (data.hasOwnProperty('page')) {
        obj['page'] = ApiClient.convertToType(data['page'], 'Number');
      }
      if (data.hasOwnProperty('pageSize')) {
        obj['pageSize'] = ApiClient.convertToType(data['pageSize'], 'Number');
      }
      if (data.hasOwnProperty('versions')) {
        obj['versions'] = ApiClient.convertToType(data['versions'], [ClickwrapVersion]);
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} accountId
   */
  exports.prototype['accountId'] = undefined;
  /**
   * 
   * @member {String} clickwrapId
   */
  exports.prototype['clickwrapId'] = undefined;
  /**
   * 
   * @member {String} clickwrapName
   */
  exports.prototype['clickwrapName'] = undefined;
  /**
   * 
   * @member {Number} minimumPagesRemaining
   */
  exports.prototype['minimumPagesRemaining'] = undefined;
  /**
   * 
   * @member {Number} page
   */
  exports.prototype['page'] = undefined;
  /**
   * 
   * @member {Number} pageSize
   */
  exports.prototype['pageSize'] = undefined;
  /**
   * 
   * @member {Array.<module:model/ClickwrapVersion>} versions
   */
  exports.prototype['versions'] = undefined;



  return exports;
}));


