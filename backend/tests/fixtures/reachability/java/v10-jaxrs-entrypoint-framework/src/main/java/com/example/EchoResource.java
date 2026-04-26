package com.example;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

/**
 * Pure JAX-RS framework_mechanism test — `@Path` + `@GET` annotated
 * method is an HTTP entry point.  Body is benign (no CVE symbols
 * in scope).  If sprint #3 cannot recognise this as a reachable
 * route handler, JAX-RS detection is broken regardless of CVE
 * symbol-resolution correctness.
 */
@Path("/echo")
public class EchoResource {

    @GET
    public String shout(@QueryParam("q") String q) {
        // Benign body — String.toUpperCase is a JDK call with no
        // third-party reachability implications.
        return q == null ? "" : q.toUpperCase();
    }
}
