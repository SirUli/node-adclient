var ldapjs = require('ldapjs');
var _ = require('lodash');
var _s = require('underscore.string');
_.mixin(_s.exports());

/*
 * Parameter Object:
 * =================
 * params.url:
 * - Description: Either a string with one AD-server or an array of ad-servers
 * - Example: 'ldap://myldapserver.mycompany.com:389'
 *
 * params.groupSearchFilter:
 * - Description: SearchFilter
 * - Example: '(objectclass=*)'
 * 
 * params.groupSearchAttributes:
 * - Description: Field used for member identification
 * - Example: 'member'
 *
 * params.groupSearchDN:
 * - Description: DN of the group where the members are stored
 * - Example: 'CN=MYAPP,OU=Applications,OU=Groups,DC=mycompany,DC=com'
 * 
 * params.masterDn:
 * - Description: DN of the master user
 * - Example: 'CN=mymaster,OU=IT,DC=mycompany,DC=com'
 *
 * params.masterPw:
 * - Description: Password of the master user
 * - Example: 'myv3rys3cr3tp4ssw0rd'
 * 
 * params.userSearchFilter:
 * - Description: SearchFilter
 * - Example: '(objectclass=*)'
 * 
 * params.userSearchAttributes:
 * - Description: Attributes of the user which should be retrieved from AD
 * - Example: ['cn', 'distinguishedName', 'sn', 'mail']
 */

function adClient(params) {
	this.params = params;
	this.masterClient = false;
	this.masterBound = false;
	this.userClient = false;
	this.userBound = false;
}

adClient.prototype.createClients = function(callback) {
	var self = this;
	self.getUrl(self.params.url, function(err, url) {
		if (!err) {
			if(self.masterClient == false) {
  				self.masterClient = ldapjs.createClient({'url': url});
			}
			if(self.userClient == false) {
  				self.userClient = ldapjs.createClient({'url': url});
			}
			callback();
		} else {
			callback(err);
		}
	});
}
	// Function used for loadbalancing
adClient.prototype.getUrl = function (paramUrl, callback) {
	if(_.isArray(paramUrl)) {
		// Remove false, null, 0, "", undefined and NaN
		paramUrl = _.compact(paramUrl);
		// Answer with a random entry
		callback(null, paramUrl[_.random(0, paramUrl.length)]);
	} else if (_.isString(paramUrl)) {
		// Answer with the url
		callback(null, paramUrl);
	} else {
		// No Url available?
		callback('No valid url given');
	}
}

adClient.prototype.bindMaster = function (callback) {
	var self = this
	self.createClients(function(err) {
		if (err) {callback(err);}
		if(self.masterBound) {
			callback();
		} else {
			self.masterClient.bind(self.params.masterDn, self.params.masterPw, callback)
		}
	});
}

// Closes all connections
adClient.prototype.close = function (callback) {
	var self = this
	if (self.masterBound) {
		self.masterClient.unbind(function(err, result) {
			self.masterBound = false;
			callback(err, result);
		});
	}
	// If master is not bound
	callback();
}

adClient.prototype.extractCNFromDN = function (dn, callback) {
	if(! _.isUndefined(dn)) {
		_.each(_.words(dn.toLowerCase(), ","), function (dndata) {
			if(_.startsWith(dndata, "cn=")) {
				callback(null, _.ltrim(dndata, 'cn='))
			}
		});
	} else {
		callback('No DN given');
	}
}

adClient.prototype.getMembersOfGroupDN = function (callback) {
	var self = this
	self.bindMaster(function(err) {
		if(err) {callback(err);}
		var searchParams = {
			filter: self.params.groupSearchFilter
			, scope: 'sub'
			, attributes: self.params.groupSearchAttributes
		};
		self.masterClient.search(self.params.groupSearchDN, searchParams, function (err, searchResult) {
			// Error handling
			if (err) {callback(err);}
			searchResult.on('error', function (err) {
				return callback(err);
			});
			// for every entry
			var resultSet = [];
			searchResult.on('searchEntry', function (searchEntry) {
				resultSet.push(searchEntry.object);
			});
			// Finally
			searchResult.on('end', function (endResult) {
				if (endResult.status !== 0) {
					return callback('Status of AD search was' + endResult.status);
				}
				switch (resultSet.length) {
					case 0:
						return callback();
					case 1:
						var memberObjects = [];
						if(! _.isUndefined(resultSet[0].member)) {
							if(! _.isString(resultSet[0].member)) {
								_.each(resultSet[0].member, function(value) {
									self.extractCNFromDN(value, function(err, valuedata) {
										memberObjects.push({cn: valuedata, dn: value})
									});
								});
							} else {
								var value = resultSet[0].member;
								self.extractCNFromDN(value, function(err, valuedata) {
									memberObjects.push({cn: valuedata, dn: value})
								});
							}	
						}
						return callback(null, memberObjects)
					default:
						return callback('Error: unexpected number of matches');
				}
			});
		});
	});	
}

/*
 * Authenticate a user with a DN and a password
 * 
 */
adClient.prototype.authUserDn = function (userDn, password, callback) {
	var self = this;
        self.createClients(function(err) {
                if (err) {callback(err);}
		self.userClient.bind(userDn, password, function(err) {
			if (err) {callback(err);}
			var searchParams = {
				filter: self.params.userSearchFilter
				, scope: 'sub'
				, attributes: self.params.userSearchAttributes
			};
			self.userClient.search(userDn, searchParams, function (err, searchResult) {
				if (err) {callback(err);}
				searchResult.on('error', function (err) {
					return callback(err);
				});
				// for every entry
				var resultSet = [];
				searchResult.on('searchEntry', function (searchEntry) {
					resultSet.push(searchEntry.object);
				});
				searchResult.on('end', function (endResult) {
					if (endResult.status !== 0) {
						return callback('Status of AD search was' + endResult.status);
					} else {
						self.userClient.unbind(function(err) {
							switch (resultSet.length) {
								case 0:
									return callback();
								case 1:
									// Filter for allowed keys:
									return callback(null, _.pick(resultSet[0], self.params.userSearchAttributes));
								default:
									return callback('Error: unexpected number of matches');
							}
						});
					}
				});
			});
		});
	});
}

adClient.prototype.authUser = function (username, password, callback) {
	var self = this;
	self.getMembersOfGroupDN(function(err, result) {
		if (err) {callback(err);}
		var user = _.where(result, {cn: username});
		if(_.isUndefined(user[0])) {
			self.close(function(err) {
                                callback('Error: User not found');
                        });
		} else {
			self.authUserDn(user[0].dn, password, function (err, userObject) {
				self.close(function(err2) {
					if (err) {callback(err, userObject);}
	                		callback(null, userObject);
        			});
			});
		}
	});
}

module.exports = adClient;
