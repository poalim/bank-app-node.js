/**
 * Created by Leonid on 30/06/14.
 */
'use strict';

/**
 * Module dependencies.
 */
var mongoose = require('mongoose'),
    Post = mongoose.model('Post'),

    _ = require('lodash');

exports.post = function (req, res, next, id) {
    Post.load(id, function (err, post) {
        if (err) return next(err);
        if (!post) return next(new Error('Failed to load post ' + id));
        req.post = post;
        next();
    });
};

exports.searchposts = function (req, res) {
//    var test = { bounds: { northeast: { latitude: 32.58595492400759, longitude: 35.29492114257812 },
//        southwest: { latitude: 31.655508574663294, longitude: 34.03698657226562 } },
//        tags: [ 'food', 'fun' ] };
    console.log(req.body);
    var searchParams = req.body;
    var bounds = searchParams.bounds;
    console.log('bounds', bounds);

    Post.find({ location: { $geoWithin: { $box: [
        [ bounds.southwest.longitude , bounds.southwest.latitude ] ,
        [ bounds.northeast.longitude , bounds.northeast.latitude  ]
    ] } } }).sort({created: -1}).exec(function (err, posts) {
            if (err) {
                return res.jsonp(500, {
                    error: 'Cannot list the  posts'
                });
            }
            res.jsonp(posts);

        });
};

/**
 * List of Posts
 */
exports.all = function (req, res) {
    Post.find().exec(function (err, posts) {
        if (err) {
            return res.jsonp(500, {
                error: 'Cannot list the posts'
            });
        }
        res.jsonp(posts);

    });
};
/**
 * Show an post
 */
exports.show = function (req, res) {
    res.jsonp(req.post);
};

exports.removeAll = function (req, res) {
    console.log('remove all posts');
    Post.remove().exec();
};
/**
 * Create an post
 */
exports.create = function (req, res) {

    console.log(req.body);
    var post = new Post(req.body);
    post.user = req.user;

    console.log(post);

    post.save(function (err) {
        if (err) {
            console.log('err:', err);
            return res.jsonp(500, {
                error: 'Cannot save the post'
            });
        }
        res.jsonp(post);

    });
};


/**
 * Update an post
 */
exports.update = function (req, res) {
    var post = req.post;

    console.log('', post);

    post = _.extend(post, req.body);

    post.save(function (err) {
        if (err) {
            return res.jsonp(500, {
                error: 'Cannot update the post'
            });
        }
        res.jsonp(post);

    });
};

/**
 * Delete an post
 */
exports.destroy = function (req, res) {
    var post = req.post;

    post.remove(function (err) {
        if (err) {
            return res.jsonp(500, {
                error: 'Cannot delete the post'
            });
        }
        res.jsonp(post);

    });
};
