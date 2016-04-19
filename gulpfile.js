'use strict';

const gulp    = require('gulp');
const babel   = require('gulp-babel');
const clean   = require('gulp-clean');
const tape    = require('gulp-tape');
const tapSpec = require('tap-spec');

gulp.task('clean-dist', () =>
  gulp.src('./dist', { read: false })
  .pipe(clean())
);

gulp.task('build-dist', ['clean-dist'], () =>
  gulp.src(['./index.js', 'lib/*.js'], { base: './' })
  .pipe(babel({ presets: ['es2015'] }))
  .pipe(gulp.dest('dist'))
);

gulp.task('test', () =>
  gulp.src('spec/*.js')
  .pipe(tape({ reporter: tapSpec() }))
);

gulp.task('default', [ 'test', 'clean-dist', 'build-dist' ], () => {});
