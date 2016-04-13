/**
  Role Manager Middleware
  @description Provides middleware that can be inserted into a router that
    serves as an access level gateway for deciding if a user can retrieve
    the given content. Must be run *after* the Verify Authtoken middleware
    so that the current user's role is set properly.
  @author tylerFowler
**/
