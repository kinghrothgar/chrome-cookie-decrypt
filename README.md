```
NAME
    chrome-cookie-decrypt

OVERVIEW
    This is a small go program that allows you to export cookies from Chrome on OS X into Netscape format. This the format expected by both `curl -b` and `yt-dlp --cookies`. Chrome stores the cookies in a sqlite file with the values encrypted. The encryption key is stored in OS X's keychain. The program will cause a prompt to pop up asking you for your password so this encryption key can be retrieved.

BUILDING
    go mod download
    go build -o chrome-cookie-decrypt ./cmd/chrome-cookie-decrypt/main.go

USAGE
    -regex string
        a regex to match cookie host key (domain) against (default ".*")

EXAMPLE
    To export the needed cookies for yt-dlp to download your private playlists (or in this example your liked videos), you would do the following:
        ./chrome-cookie-decrypt -regex '^\.(google|youtube)\.com$' > cookies.txt
        yt-dlp -N 10 -i --write-info-json --write-description --download-archive liked.list --cookies cookies.txt https://www.youtube.com/playlist\?list\=L
```
