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
    define(['ApiClient', 'model/ClickwrapVersionDeleteResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ClickwrapVersionDeleteResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.ClickwrapVersionsDeleteResponse = factory(root.DocusignClick.ApiClient, root.DocusignClick.ClickwrapVersionDeleteResponse);
  }
}(this, function(ApiClient, ClickwrapVersionDeleteResponse) {
  'use strict';


  /**
   * The ClickwrapVersionsDeleteResponse model module.
   * @module model/ClickwrapVersionsDeleteResponse
   */

  /**
   * Constructs a new <code>ClickwrapVersionsDeleteResponse</code>.
   * @alias module:model/ClickwrapVersionsDeleteResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapVersionsDeleteResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapVersionsDeleteResponse} obj Optional instance to populate.
   * @return {module:model/ClickwrapVersionsDeleteResponse} The populated <code>ClickwrapVersionsDeleteResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('clickwrapId')) {
        obj['clickwrapId'] = ApiClient.convertToType(data['clickwrapId'], 'String');
      }
      if (data.hasOwnProperty('clickwrapName')) {
        obj['clickwrapName'] = ApiClient.convertToType(data['clickwrapName'], 'String');
      }
      if (data.hasOwnProperty('versions')) {
        obj['versions'] = ApiClient.convertToType(data['versions'], [ClickwrapVersionDeleteResponse]);
      }
    }
    return obj;
  }

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
   * @member {Array.<module:model/ClickwrapVersionDeleteResponse>} versions
   */
  exports.prototype['versions'] = undefined;



  return exports;
}));


