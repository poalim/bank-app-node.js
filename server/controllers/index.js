'use strict';

var mean = require('meanio');
var config = require('../config/config');

exports.render = function(req, res) {

    var modules = [];

    // Preparing angular modules list with dependencies
    for (var name in mean.modules) {
        modules.push({
            name: name,
            module: 'mean.' + name,
            angularDependencies: mean.modules[name].angularDependencies
        });
    }

    function isAdmin() {
        return req.user && req.user.roles.indexOf('admin') !== -1;
    }

    // Send some basic starting info to the view
    console.log('req.user:', req.user);
    res.render('index', {
        user: req.user ? {
            name: req.user.name,
            _id: req.user._id,
            username: req.user.username,
            instagram : req.user.instagram,
            instagramAccessToken : req.user.instagramAccessToken,
            roles: req.user.roles
        } : {},
        modules: modules,
        isAdmin: isAdmin,
        config : config,
        adminEnabled: isAdmin() && mean.moduleEnabled('mean-admin')
    });
};
