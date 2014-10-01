/**
 * Created by Leonid on 02/08/14.
 *
 * Entry for user post, for easy access
 */
'use strict';

/**
 * Module dependencies.
 */
var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

var UserRootSchema = new Schema({
    createdAt: {type: Date, default: Date.now},
    last_touched: {type: Date, default: Date.now},
    posts : [{ type : Schema.ObjectId, ref : 'posts' }],
    user: {
        type: Schema.ObjectId,
        ref: 'User',
        unique: true,
        index : true
    }
});

mongoose.model('UserRoot', UserRootSchema);