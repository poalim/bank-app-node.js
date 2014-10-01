/**
 * Created by Leonid on 30/06/14.
 */
'use strict';

/**
 * Module dependencies.
 */
var mongoose = require('mongoose'),
    Schema = mongoose.Schema;


/**
 * Post Schema
 */
var PostSchema = new Schema({
    created: {
        type: Date,
        default: Date.now
    },
    content: {
        type: String,
        required: true,
        trim: true
    },
    tags: {
        type: [String],
        trim: true
    },
    locationHash : {
        'type': {
            type: String,
            required: true,
            enum: ['Point', 'LineString', 'Polygon'],
            default: 'Point'
        },
        coordinates: []
    },
    location: {
        'type': {
            type: String,
            required: true,
            enum: ['Point', 'LineString', 'Polygon'],
            default: 'Point'
        },

        coordinates: []
    },
    user: {
        type: Schema.ObjectId,
        ref: 'User'
    },
    comments : [String]

});

PostSchema.index({location: '2dsphere'});

/**
 * Validations
 */
PostSchema.path('content').validate(function (content) {
    return !!content;
}, 'Content cannot be blank');

/**
 * Statics
 */
PostSchema.statics.load = function (id, cb) {
    this.findOne({
        _id: id
    }).populate('user', 'name username').exec(cb);
};

mongoose.model('Post', PostSchema);
