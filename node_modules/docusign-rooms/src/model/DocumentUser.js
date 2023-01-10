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
    root.DocusignRooms.DocumentUser = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DocumentUser model module.
   * @module model/DocumentUser
   */

  /**
   * Constructs a new <code>DocumentUser</code>.
   * @alias module:model/DocumentUser
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DocumentUser</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DocumentUser} obj Optional instance to populate.
   * @return {module:model/DocumentUser} The populated <code>DocumentUser</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('userId')) {
        obj['userId'] = ApiClient.convertToType(data['userId'], 'Number');
      }
      if (data.hasOwnProperty('documentId')) {
        obj['documentId'] = ApiClient.convertToType(data['documentId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('hasAccess')) {
        obj['hasAccess'] = ApiClient.convertToType(data['hasAccess'], 'Boolean');
      }
      if (data.hasOwnProperty('canApproveTask')) {
        obj['canApproveTask'] = ApiClient.convertToType(data['canApproveTask'], 'Boolean');
      }
      if (data.hasOwnProperty('canAssignToTaskList')) {
        obj['canAssignToTaskList'] = ApiClient.convertToType(data['canAssignToTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canCopy')) {
        obj['canCopy'] = ApiClient.convertToType(data['canCopy'], 'Boolean');
      }
      if (data.hasOwnProperty('canDelete')) {
        obj['canDelete'] = ApiClient.convertToType(data['canDelete'], 'Boolean');
      }
      if (data.hasOwnProperty('canRemoveFromTaskList')) {
        obj['canRemoveFromTaskList'] = ApiClient.convertToType(data['canRemoveFromTaskList'], 'Boolean');
      }
      if (data.hasOwnProperty('canRemoveApproval')) {
        obj['canRemoveApproval'] = ApiClient.convertToType(data['canRemoveApproval'], 'Boolean');
      }
      if (data.hasOwnProperty('canRename')) {
        obj['canRename'] = ApiClient.convertToType(data['canRename'], 'Boolean');
      }
      if (data.hasOwnProperty('canShare')) {
        obj['canShare'] = ApiClient.convertToType(data['canShare'], 'Boolean');
      }
      if (data.hasOwnProperty('canViewActivity')) {
        obj['canViewActivity'] = ApiClient.convertToType(data['canViewActivity'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {Number} userId
   */
  exports.prototype['userId'] = undefined;
  /**
   * @member {Number} documentId
   */
  exports.prototype['documentId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Boolean} hasAccess
   */
  exports.prototype['hasAccess'] = undefined;
  /**
   * @member {Boolean} canApproveTask
   */
  exports.prototype['canApproveTask'] = undefined;
  /**
   * @member {Boolean} canAssignToTaskList
   */
  exports.prototype['canAssignToTaskList'] = undefined;
  /**
   * @member {Boolean} canCopy
   */
  exports.prototype['canCopy'] = undefined;
  /**
   * @member {Boolean} canDelete
   */
  exports.prototype['canDelete'] = undefined;
  /**
   * @member {Boolean} canRemoveFromTaskList
   */
  exports.prototype['canRemoveFromTaskList'] = undefined;
  /**
   * @member {Boolean} canRemoveApproval
   */
  exports.prototype['canRemoveApproval'] = undefined;
  /**
   * @member {Boolean} canRename
   */
  exports.prototype['canRename'] = undefined;
  /**
   * @member {Boolean} canShare
   */
  exports.prototype['canShare'] = undefined;
  /**
   * @member {Boolean} canViewActivity
   */
  exports.prototype['canViewActivity'] = undefined;



  return exports;
}));


