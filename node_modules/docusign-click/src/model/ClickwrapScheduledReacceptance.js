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
    root.DocusignClick.ClickwrapScheduledReacceptance = factory(root.DocusignClick.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The ClickwrapScheduledReacceptance model module.
   * @module model/ClickwrapScheduledReacceptance
   */

  /**
   * Constructs a new <code>ClickwrapScheduledReacceptance</code>.
   * @alias module:model/ClickwrapScheduledReacceptance
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapScheduledReacceptance</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapScheduledReacceptance} obj Optional instance to populate.
   * @return {module:model/ClickwrapScheduledReacceptance} The populated <code>ClickwrapScheduledReacceptance</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('recurrenceInterval')) {
        obj['recurrenceInterval'] = ApiClient.convertToType(data['recurrenceInterval'], 'Number');
      }
      if (data.hasOwnProperty('recurrenceIntervalType')) {
        obj['recurrenceIntervalType'] = ApiClient.convertToType(data['recurrenceIntervalType'], 'String');
      }
      if (data.hasOwnProperty('startDateTime')) {
        obj['startDateTime'] = ApiClient.convertToType(data['startDateTime'], Object);
      }
    }
    return obj;
  }

  /**
   * 
   * @member {Number} recurrenceInterval
   */
  exports.prototype['recurrenceInterval'] = undefined;
  /**
   * 
   * @member {String} recurrenceIntervalType
   */
  exports.prototype['recurrenceIntervalType'] = undefined;
  /**
   * 
   * @member {Object} startDateTime
   */
  exports.prototype['startDateTime'] = undefined;



  return exports;
}));


