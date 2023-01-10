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
    root.DocusignClick.ClickwrapTransferRequest = factory(root.DocusignClick.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ClickwrapTransferRequest model module.
   * @module model/ClickwrapTransferRequest
   */

  /**
   * Constructs a new <code>ClickwrapTransferRequest</code>.
   * @alias module:model/ClickwrapTransferRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapTransferRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapTransferRequest} obj Optional instance to populate.
   * @return {module:model/ClickwrapTransferRequest} The populated <code>ClickwrapTransferRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('transferFromUserId')) {
        obj['transferFromUserId'] = ApiClient.convertToType(data['transferFromUserId'], 'String');
      }
      if (data.hasOwnProperty('transferToUserId')) {
        obj['transferToUserId'] = ApiClient.convertToType(data['transferToUserId'], 'String');
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} transferFromUserId
   */
  exports.prototype['transferFromUserId'] = undefined;
  /**
   * 
   * @member {String} transferToUserId
   */
  exports.prototype['transferToUserId'] = undefined;



  return exports;
}));


