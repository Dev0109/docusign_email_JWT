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
    define(['ApiClient', 'model/GroupForm'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./GroupForm'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.FormGroup = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.GroupForm);
  }
}(this, function(ApiClient, GroupForm) {
  'use strict';


  /**
   * The FormGroup model module.
   * @module model/FormGroup
   */

  /**
   * Constructs a new <code>FormGroup</code>.
   * @alias module:model/FormGroup
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>FormGroup</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/FormGroup} obj Optional instance to populate.
   * @return {module:model/FormGroup} The populated <code>FormGroup</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('formGroupId')) {
        obj['formGroupId'] = ApiClient.convertToType(data['formGroupId'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('officeIds')) {
        obj['officeIds'] = ApiClient.convertToType(data['officeIds'], ['Number']);
      }
      if (data.hasOwnProperty('forms')) {
        obj['forms'] = ApiClient.convertToType(data['forms'], [GroupForm]);
      }
    }
    return obj;
  }

  /**
   * @member {String} formGroupId
   */
  exports.prototype['formGroupId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Array.<Number>} officeIds
   */
  exports.prototype['officeIds'] = undefined;
  /**
   * @member {Array.<module:model/GroupForm>} forms
   */
  exports.prototype['forms'] = undefined;



  return exports;
}));


