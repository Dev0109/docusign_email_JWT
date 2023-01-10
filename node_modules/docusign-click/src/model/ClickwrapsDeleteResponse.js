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
    define(['ApiClient', 'model/ClickwrapDeleteResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ClickwrapDeleteResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.ClickwrapsDeleteResponse = factory(root.DocusignClick.ApiClient, root.DocusignClick.ClickwrapDeleteResponse);
  }
}(this, function(ApiClient, ClickwrapDeleteResponse) {
  'use strict';


  /**
   * The ClickwrapsDeleteResponse model module.
   * @module model/ClickwrapsDeleteResponse
   */

  /**
   * Constructs a new <code>ClickwrapsDeleteResponse</code>.
   * @alias module:model/ClickwrapsDeleteResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapsDeleteResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapsDeleteResponse} obj Optional instance to populate.
   * @return {module:model/ClickwrapsDeleteResponse} The populated <code>ClickwrapsDeleteResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('clickwraps')) {
        obj['clickwraps'] = ApiClient.convertToType(data['clickwraps'], [ClickwrapDeleteResponse]);
      }
    }
    return obj;
  }

  /**
   * 
   * @member {Array.<module:model/ClickwrapDeleteResponse>} clickwraps
   */
  exports.prototype['clickwraps'] = undefined;



  return exports;
}));


