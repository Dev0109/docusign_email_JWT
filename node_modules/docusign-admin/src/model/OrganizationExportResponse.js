/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/OrgExportSelectedAccount', 'model/OrgExportSelectedDomain', 'model/OrganizationExportRequestorResponse', 'model/OrganizationExportTaskResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrgExportSelectedAccount'), require('./OrgExportSelectedDomain'), require('./OrganizationExportRequestorResponse'), require('./OrganizationExportTaskResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationExportResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrgExportSelectedAccount, root.DocusignAdmin.OrgExportSelectedDomain, root.DocusignAdmin.OrganizationExportRequestorResponse, root.DocusignAdmin.OrganizationExportTaskResponse);
  }
}(this, function(ApiClient, OrgExportSelectedAccount, OrgExportSelectedDomain, OrganizationExportRequestorResponse, OrganizationExportTaskResponse) {
  'use strict';


  /**
   * The OrganizationExportResponse model module.
   * @module model/OrganizationExportResponse
   */

  /**
   * Constructs a new <code>OrganizationExportResponse</code>.
   * @alias module:model/OrganizationExportResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationExportResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationExportResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationExportResponse} The populated <code>OrganizationExportResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('requestor')) {
        obj['requestor'] = OrganizationExportRequestorResponse.constructFromObject(data['requestor']);
      }
      if (data.hasOwnProperty('created')) {
        obj['created'] = ApiClient.convertToType(data['created'], 'Date');
      }
      if (data.hasOwnProperty('last_modified')) {
        obj['last_modified'] = ApiClient.convertToType(data['last_modified'], 'Date');
      }
      if (data.hasOwnProperty('completed')) {
        obj['completed'] = ApiClient.convertToType(data['completed'], 'Date');
      }
      if (data.hasOwnProperty('expires')) {
        obj['expires'] = ApiClient.convertToType(data['expires'], 'Date');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('selected_accounts')) {
        obj['selected_accounts'] = ApiClient.convertToType(data['selected_accounts'], [OrgExportSelectedAccount]);
      }
      if (data.hasOwnProperty('selected_domains')) {
        obj['selected_domains'] = ApiClient.convertToType(data['selected_domains'], [OrgExportSelectedDomain]);
      }
      if (data.hasOwnProperty('metadata_url')) {
        obj['metadata_url'] = ApiClient.convertToType(data['metadata_url'], 'String');
      }
      if (data.hasOwnProperty('percent_completed')) {
        obj['percent_completed'] = ApiClient.convertToType(data['percent_completed'], 'Number');
      }
      if (data.hasOwnProperty('number_rows')) {
        obj['number_rows'] = ApiClient.convertToType(data['number_rows'], 'Number');
      }
      if (data.hasOwnProperty('size_bytes')) {
        obj['size_bytes'] = ApiClient.convertToType(data['size_bytes'], 'Number');
      }
      if (data.hasOwnProperty('results')) {
        obj['results'] = ApiClient.convertToType(data['results'], [OrganizationExportTaskResponse]);
      }
      if (data.hasOwnProperty('success')) {
        obj['success'] = ApiClient.convertToType(data['success'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {module:model/OrganizationExportRequestorResponse} requestor
   */
  exports.prototype['requestor'] = undefined;
  /**
   * @member {Date} created
   */
  exports.prototype['created'] = undefined;
  /**
   * @member {Date} last_modified
   */
  exports.prototype['last_modified'] = undefined;
  /**
   * @member {Date} completed
   */
  exports.prototype['completed'] = undefined;
  /**
   * @member {Date} expires
   */
  exports.prototype['expires'] = undefined;
  /**
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {Array.<module:model/OrgExportSelectedAccount>} selected_accounts
   */
  exports.prototype['selected_accounts'] = undefined;
  /**
   * @member {Array.<module:model/OrgExportSelectedDomain>} selected_domains
   */
  exports.prototype['selected_domains'] = undefined;
  /**
   * @member {String} metadata_url
   */
  exports.prototype['metadata_url'] = undefined;
  /**
   * @member {Number} percent_completed
   */
  exports.prototype['percent_completed'] = undefined;
  /**
   * @member {Number} number_rows
   */
  exports.prototype['number_rows'] = undefined;
  /**
   * @member {Number} size_bytes
   */
  exports.prototype['size_bytes'] = undefined;
  /**
   * @member {Array.<module:model/OrganizationExportTaskResponse>} results
   */
  exports.prototype['results'] = undefined;
  /**
   * @member {Boolean} success
   */
  exports.prototype['success'] = undefined;



  return exports;
}));


