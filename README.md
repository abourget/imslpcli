imslp.org.har contains a session of using the web interface, and manipulate playlists, add stuff to it..

Study it and come up with a cobra-based Go IMSLP CLI tool. Use `resty.dev/v3` for all outgoing calls. Create it as a nice library distinct from the CLI in client.go and main.go that will make use of it.

I know that it uses a client-side database for storing stuff.. but we'll make it quite simple. A `sync` command that will populate a .json file with all our scores, and perhaps another one with all of the setlists?
Then manipulations can work on that, updates, would tweak the local version of it and push the updates with their sync.put thing.


