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
    root.DocusignRooms.FormForAdd = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The FormForAdd model module.
   * @module model/FormForAdd
   */

  /**
   * Constructs a new <code>FormForAdd</code>.
   * @alias module:model/FormForAdd
   * @class
   * @param formId {String} 
   */
  var exports = function(formId) {
    var _this = this;

    _this['formId'] = formId;
  };

  /**
   * Constructs a <code>FormForAdd</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/FormForAdd} obj Optional instance to populate.
   * @return {module:model/FormForAdd} The populated <code>FormForAdd</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('formId')) {
        obj['formId'] = ApiClient.convertToType(data['formId'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} formId
   */
  exports.prototype['formId'] = undefined;



  return exports;
}));


