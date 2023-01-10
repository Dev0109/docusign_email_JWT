/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
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
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GroupForm = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The GroupForm model module.
   * @module model/GroupForm
   */

  /**
   * Constructs a new <code>GroupForm</code>.
   * @alias module:model/GroupForm
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GroupForm</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GroupForm} obj Optional instance to populate.
   * @return {module:model/GroupForm} The populated <code>GroupForm</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('formId')) {
        obj['formId'] = ApiClient.convertToType(data['formId'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('isRequired')) {
        obj['isRequired'] = ApiClient.convertToType(data['isRequired'], 'Boolean');
      }
      if (data.hasOwnProperty('lastUpdatedDate')) {
        obj['lastUpdatedDate'] = ApiClient.convertToType(data['lastUpdatedDate'], 'Date');
      }
    }
    return obj;
  }

  /**
   * @member {String} formId
   */
  exports.prototype['formId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Boolean} isRequired
   */
  exports.prototype['isRequired'] = undefined;
  /**
   * @member {Date} lastUpdatedDate
   */
  exports.prototype['lastUpdatedDate'] = undefined;



  return exports;
}));


