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
    define(['ApiClient', 'model/ClickwrapScheduledReacceptance', 'model/DataField', 'model/DisplaySettings', 'model/Document'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ClickwrapScheduledReacceptance'), require('./DataField'), require('./DisplaySettings'), require('./Document'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.ClickwrapRequest = factory(root.DocusignClick.ApiClient, root.DocusignClick.ClickwrapScheduledReacceptance, root.DocusignClick.DataField, root.DocusignClick.DisplaySettings, root.DocusignClick.Document);
  }
}(this, function(ApiClient, ClickwrapScheduledReacceptance, DataField, DisplaySettings, Document) {
  'use strict';


  /**
   * The ClickwrapRequest model module.
   * @module model/ClickwrapRequest
   */

  /**
   * Constructs a new <code>ClickwrapRequest</code>.
   * @alias module:model/ClickwrapRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>ClickwrapRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ClickwrapRequest} obj Optional instance to populate.
   * @return {module:model/ClickwrapRequest} The populated <code>ClickwrapRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('clickwrapName')) {
        obj['clickwrapName'] = ApiClient.convertToType(data['clickwrapName'], 'String');
      }
      if (data.hasOwnProperty('dataFields')) {
        obj['dataFields'] = ApiClient.convertToType(data['dataFields'], [DataField]);
      }
      if (data.hasOwnProperty('displaySettings')) {
        obj['displaySettings'] = DisplaySettings.constructFromObject(data['displaySettings']);
      }
      if (data.hasOwnProperty('documents')) {
        obj['documents'] = ApiClient.convertToType(data['documents'], [Document]);
      }
      if (data.hasOwnProperty('fieldsToNull')) {
        obj['fieldsToNull'] = ApiClient.convertToType(data['fieldsToNull'], 'String');
      }
      if (data.hasOwnProperty('isMajorVersion')) {
        obj['isMajorVersion'] = ApiClient.convertToType(data['isMajorVersion'], 'Boolean');
      }
      if (data.hasOwnProperty('isShared')) {
        obj['isShared'] = ApiClient.convertToType(data['isShared'], 'Boolean');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('requireReacceptance')) {
        obj['requireReacceptance'] = ApiClient.convertToType(data['requireReacceptance'], 'Boolean');
      }
      if (data.hasOwnProperty('scheduledDate')) {
        obj['scheduledDate'] = ApiClient.convertToType(data['scheduledDate'], Object);
      }
      if (data.hasOwnProperty('scheduledReacceptance')) {
        obj['scheduledReacceptance'] = ClickwrapScheduledReacceptance.constructFromObject(data['scheduledReacceptance']);
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
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
   * @member {String} clickwrapName
   */
  exports.prototype['clickwrapName'] = undefined;
  /**
   * 
   * @member {Array.<module:model/DataField>} dataFields
   */
  exports.prototype['dataFields'] = undefined;
  /**
   * @member {module:model/DisplaySettings} displaySettings
   */
  exports.prototype['displaySettings'] = undefined;
  /**
   * 
   * @member {Array.<module:model/Document>} documents
   */
  exports.prototype['documents'] = undefined;
  /**
   * 
   * @member {String} fieldsToNull
   */
  exports.prototype['fieldsToNull'] = undefined;
  /**
   * 
   * @member {Boolean} isMajorVersion
   */
  exports.prototype['isMajorVersion'] = undefined;
  /**
   * 
   * @member {Boolean} isShared
   */
  exports.prototype['isShared'] = undefined;
  /**
   * 
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * 
   * @member {Boolean} requireReacceptance
   */
  exports.prototype['requireReacceptance'] = undefined;
  /**
   * 
   * @member {Object} scheduledDate
   */
  exports.prototype['scheduledDate'] = undefined;
  /**
   * @member {module:model/ClickwrapScheduledReacceptance} scheduledReacceptance
   */
  exports.prototype['scheduledReacceptance'] = undefined;
  /**
   * 
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
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


