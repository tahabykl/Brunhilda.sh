#!/bin/bash
#title           :brunhilda.sh
#description     :Automatic recon and scan script for web application security
#date            :20210501
#bash_version    :5.1.4(1)-release

## TODOs:
#       * Test for 200 dummy pages before running ffuf
#       * Fix telegram update issue

NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHTGRAY='\033[0;37m'
DARKGRAY='\033[1;30m'
LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHTBLUE='\033[1;34m'
LIGHTPURPLE='\033[1;35m'
LIGHTCYAN='\033[1;36m'
WHITE='\033[1;37m'

# Default flags that were set.
[ -z "$ALTDNS_WORDS" ] && ALTDNS_WORDS="$HOME/wordlists/altdns/words.txt"
[ -z "$MASSDNS_RESOLVERS" ] && MASSDNS_RESOLVERS="$HOME/wordlists/massdns/resolvers.txt"
[ -z "$SUBJACK_FINGERPRINTS" ] && SUBJACK_FINGERPRINTS="$HOME/wordlists/subjack/fingerprints.json"
[ -z "$FUZZ_WORDLIST" ] && FUZZ_WORDLIST=""
[ -z "$FUZZ_WORDLIST_API" ] && FUZZ_WORDLIST_API=""
[ -z "$FFUF_OPTS" ] && FFUF_OPTS=""
[ -z "$BURPSUITE_URL" ] && BURPSUITE_URL="http://localhost:1337/"
[ -z "$BURPSUITE_MAXSCANS" ] && BURPSUITE_MAXSCANS="4"
[ -z "$BURPSUITE_APIKEY" ] && BURPSUITE_APIKEY="1111111111111111111111111111111111111"
[ -z "$DALFOX_SERVER" ] && DALFOX_SERVER="1.1.1.1:6664"
[ -z "$DALFOX_OPTIONS" ] && DALFOX_OPTIONS="{}"
[ -z "$TELEGRAM_CHATID" ] && TELEGRAM_CHATID="11111111111111111111111111111111"
[ -z "$TELEGRAM_TOKEN" ] && TELEGRAM_TOKEN="111111111111111111111111111111111"
[ -z "$HTTPX_PORTS" ] && HTTPX_PORTS="80,443,8080,8443,8009"
[ -z "$HTTPX_FILTERED_PORTS" ] && HTTPX_FILTERED_PORTS="302,300,301"
[ -z "$BAR_LENGTH" ] && BAR_LENGTH="40"

[ -n "$HTTPX_FILTERED_PORTS" ] && HTTPX_FILTERED_PORTS="-fc $HTTPX_FILTERED_PORTS"

thread_num=32
httpx_timeout=-1
process_num=3
httpx_blacklist=""
override=""
verbose=""

# Flags
devtest=""
dalfox=""
javascript=""
notify=""
screenshot=""
takeover=""
gau=""
fuzz=""
permutate=""

# Variables used for update
SCRIPT=$(which "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
SCRIPTNAME="$(echo "$0" | sed "s/.*\///g")"
ARGS="$@"
BRANCH="master"

function tool_check {
        # TODO check for all the non UNIX-standard tools that needs to be installed on the system.
        return
}

# Function to print help message
function help {
        echo -e "\n${GREEN}Usage:${NC} brunhilda.sh [FLAGS] [TARGET_FILE]\n"
        echo -e "${BLUE}Flags:${NC}"
        echo -e "   -t  --thread"
        echo -e "       Select the number of threads to be used.(${PURPLE}$thread_num${NC})"
        echo -e "   -ht  --httpx-timeout"
        echo -e "       Timeout for httpx in seconds, -1 disables timeout.(${PURPLE}$httpx_timeout${NC})"
        echo -e "   -o --override"
        echo -e "       Override scan targets if they were scanned before"
        echo -e "   -hb  --httpx-blacklist"
        echo -e "       A file contains regex's which is used to filter useless subdomains."
        echo -e "   -pn  --process-number"
        echo -e "       Number of simultaneous processes to run.(${PURPLE}$process_num${NC})"
        echo -e "   -b  --burpscan"
        echo -e "       Add all live endpoints to burpsuite scanner."
        echo -e "   -d  --dalfox"
        echo -e "       Scan all live endpoints with dalfox"
        echo -e "   -j  --javascript"
        echo -e "       Analyse javascript files (requires gau to be enabled)."
        echo -e "   -s  --screenshot"
        echo -e "       Screenshot live endpoints with aquatone."
        echo -e "   -n  --notify"
        echo -e "       Send notifications through telegram."
        echo -e "   -tk  --takeover"
        echo -e "       Test for subdomain takeover for all targets."
        echo -e "   -g  --gau"
        echo -e "       Discover urls using gau."
        echo -e "   -f  --fuzz"
        echo -e "       Fuzz all live endpoints with ffuf."
        echo -e "   -p  --permutate"
        echo -e "       Create permutations of subdomains with altdns."
        echo -e "   -v  --verbose"
        echo -e "       Enable verbose mode.\n"
        echo -e "${BLUE}Target File:${NC}"
        echo -e "   The Target file must be a CSV file with 7 fields in the following order:"
        echo -e "   domain, burpscan, dalfox, screenshot, takeover, gau, fuzz, permutate, javascript."
        echo -e "   You can also pipe the data to the program if you pass - as the target file.\n"
        echo -e "${BLUE}Environment Variables:${NC}"
        echo -e "   ${YELLOW}ALTDNS_WORDS${NC} ($ALTDNS_WORDS)"
        echo -e "   ${YELLOW}MASSDNS_RESOLVERS${NC} ($MASSDNS_RESOLVERS)"
        echo -e "   ${YELLOW}SUBJACK_FINGERPRINTS${NC} ($SUBJACK_FINGERPRINTS)"
        echo -e "   ${YELLOW}FUZZ_WORDLIST${NC} ($FUZZ_WORDLIST)"
        echo -e "   ${YELLOW}FUZZ_WORDLIST_API${NC} ($FUZZ_WORDLIST_API)"
        echo -e "   ${YELLOW}FFUF_OPTS${NC} ($FFUF_OPTS)"
        echo -e "   ${YELLOW}HTTPX_PORTS${NC} ($HTTPX_PORTS)"
        echo -e "   ${YELLOW}HTTPX_FILTERED_PORTS${NC} ($HTTPX_FILTERED_PORTS)"
        echo -e "   ${YELLOW}DALFOX_SERVER${NC} ($DALFOX_SERVER)"
        echo -e "   ${YELLOW}DALFOX_OPTIONS${NC} ($DALFOX_OPTIONS)"
        echo -e "   ${YELLOW}BURPSUITE_URL${NC} ($BURPSUITE_URL)"
        echo -e "   ${YELLOW}BURPSUITE_APIKEY${NC} ($( echo "$BURPSUITE_APIKEY" | sed "s/./*/g"))"
        echo -e "   ${YELLOW}TELEGRAM_CHATID${NC} ($TELEGRAM_CHATID)"
        echo -e "   ${YELLOW}TELEGRAM_TOKEN${NC} ($( echo "$TELEGRAM_TOKEN" | sed "s/./*/g"))"
        echo -e "   ${YELLOW}BAR_LENGTH${NC} ($BAR_LENGTH)"
        echo -e ""
        exit 1
}

info(){
        printf "[\e[32mINFO\e[0m]: $(date --rfc-2822) (${PURPLE}$2${NC}): $1\n" >> $logfile
}

debug(){
        [ $verbose ] &&\
        printf "[\e[33mDEBUG\e[0m]: $(date --rfc-2822) (${PURPLE}$2${NC}): $1\n" >> $logfile
}

error(){
        printf "[\e[31mERROR\e[0m]: $(date --rfc-2822) (${PURPLE}$2${NC}): $1\n" >> $logfile
}

info_out(){
  printf "[\e[32mINFO\e[0m]: $1\n"
}

error_out(){
  printf "[\e[31mERROR\e[0m]:$1\n"
}

# Echo help message if no parameters are provided
if [ $# == 0 ]
then
        help
fi

params_orig="$@"

while [[ $# -gt 1 ]]
do
        key="$1"
        case $key in
                -f|--fuzz)
                        fuzz="1"
                        shift
                        ;;
                -p|--permutate)
                        permutate="1"
                        shift
                        ;;
                -s|--screenshot)
                        screenshot=true
                        shift
                        ;;
                -hb|--httpx-blacklist)
                        [ ! -f "$2" ] && error_out "File $2 does not exist!" && exit 1
                        httpx_blacklist="$(sed ':a;N;$!ba;s/\n/|/g' "$2")"
                        shift 2
                        ;;
                -g|--gau)
                        gau=true
                        shift
                        ;;
                -j|--javascript)
                        javascript=true
                        gau=true
                        shift
                        ;;
                -d|--dalfox)
                        dalfox=true
                        shift
                        ;;
                -o|--override)
                        override=true
                        shift
                        ;;
                -tk|--takeover)
                        takeover=true
                        shift
                        ;;
                -b|--burpscan)
                        burpscan="true"
                        shift
                        ;;
                -n|--notify)
                        notify=true
                        shift
                        ;;
                -t|--thread)
                        thread_num="$2"
                        shift 2
                        ;;
                -ht|--httpx-timeout)
                        httpx_timeout="$2"
                        shift 2
                        ;;
                -pn|--process-number)
                        process_num="$2"
                        shift 2
                        ;;
                -v|--verbose)
                        verbose=true
                        shift
                        ;;
                --devtest)
                        devtest=$2
                        shift 2
                        ;;
                *)
                        help
                        ;;
        esac
done

# Always print help text
[ "$1" = "-h" ] || [ "$1" = "--help" ] && help

startloc="$(pwd)"
logfile="$startloc/brunhilda.log"
temploc="/tmp/brunhilda_$$"
mkdir -p "$temploc"

declare -A portmap
portmap=( ["443"]="80" ["8443"]="8080")

# Auto pull updates from gist
if [ -z "$devtest" ]; then
        cd $SCRIPTPATH
        info_out "Checking for updates"
        git fetch > /dev/null 2> /dev/null

        [ -n "$(git diff --name-only origin/$BRANCH | grep $SCRIPTNAME)" ] && {
                info_out "Found a new version of me, updating myself..."
                git pull --force > /dev/null 2> /dev/null
                git checkout $BRANCH > /dev/null 2> /dev/null
                git pull --force > /dev/null 2> /dev/null
                info_out "Running the new version..."
                sleep 1
                cd "$startloc"
                exec "$SCRIPTNAME" $params_orig

                # Now exit this old instance
                exit 1
        }
        cd "$startloc"

        # Check if domfile exists
        domfile=$1
        [ ! -f "$domfile" ] && [ -z "$devtest" ] && [ "$domfile" != "-" ] && error_out "File $domfile does not exist!" && exit 1

        info_out "Launching recon on ${PURPLE}$(wc -l "$domfile" | cut -d" " -f1)${NC} domains"

        echo "" > $logfile

        tool_check
fi

if [ -z "$TMUX" ] && [ -z "$STY" ]; then
        tmux new-session -s brunhilda_$$ bash -c "$SCRIPTNAME $params_orig ; bash" || screen -S brunhilda_$$ -m bash -c "$SCRIPTNAME $params_orig && bash"
        exit 0
else
        if [ "$TMUX" ]; then
                tmux split-window -h "less +F -f -r \"$logfile\""
        else
                if [ -z "$devtest" ]; then
                        screen -X split -v
                        screen -X focus
                        screen -t logs less +F -f -r "$logfile"
                fi
        fi
fi

launch_burp_scan(){
        while read -r i; do
                retry_count=0
                status_code=""
                while [ ! "$status_code" = "201" ] && [ "$retry_count" -lt 3 ]; do # Retry adding the target 3 times
                        debug "Sending to burpsuite for scan" $i
                        status_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BURPSUITE_URL/$BURPSUITE_APIKEY/v0.1/scan" -d "{\"urls\":[\"$i\"]}")
                        ((retry_count++))
                done
        done < $1
}

dalfox_send(){
        while read -r i; do
                retry_count=0
                status_code=""
                while [ ! "$status_code" = "200" ] && [ "$retry_count" -lt 3 ]; do # Retry adding the target 3 times
                        debug "Sending to dalfox for scan" $i
                        status_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$DALFOX_SERVER/scan" -d "{\"url\":\"$i\",\"options\":$DALFOX_OPTIONS}")
                        ((retry_count++))
                done
        done < $1
}

burp_pool=/tmp/burp_pool_$$
watch_burp_pool(){

}

add_to_burp_pool(){

}

# The main scanner function
release_the_hounds(){
        IFS=, read -r domain dom_dalfox dom_burpscan dom_screenshot dom_takeover\
                dom_gau dom_fuzz dom_permutate dom_javascript <<< $1
        [ -z "$domain" ] && return
        [ "$domain" = "domain" ] && return # Skip header

        if [ -d $startloc/$domain ] && [  -z "$override" ]; then
                info "Already scanned, skipping" $domain
                return
        fi
        mkdir -p "$temploc/$domain"
        cd "$temploc/$domain";

        info "Enumerating subdomains" $domain

        debug "Starting subfinder scan." $domain;
        subfinder -silent -d $domain -t $thread_num -recursive > "$temploc/$domain/"subdomains.subfinder 2> /dev/null;

        debug "Starting ${PURPLE}assetfinder${NC} scan." $domain;
        assetfinder -subs-only $domain > "$temploc/$domain/"subdomains.assetfinder 2> /dev/null;

        debug "Starting ${PURPLE}findomain${NC} scan." $domain;
        findomain -q -t $domain > "$temploc/$domain/"subdomains.findomain 2> /dev/null;

        cat "$temploc/$domain/"subdomains.* | sort -u | uniq > "$temploc/$domain/"subdomains.all
        info "Done scanning, found ${PURPLE}$(wc -l "$temploc/$domain/"subdomains.all | cut -d " " -f 1)${NC} subdomains." $domain

        if [ "$httpx_blacklist" ]; then
                grep -Ev "$httpx_blacklist" "$temploc/$domain/"subdomains.all > "$temploc/$domain/"subdomains.filtered
                debug "${PURPLE}$(wc -l "$temploc/$domain/"subdomains.filtered | cut -d " " -f 1)${NC} subdomains remain after filtering." $domain
        else
                cp "$temploc/$domain/"subdomains.all "$temploc/$domain/"subdomains.filtered
        fi

        if [ "$dom_permutate" ] || [ "$permutate" ]; then
                info "Permutating subdomains and resolving them" $domain
                debug "Starting ${PURPLE}altdns${NC} subdomain permutation." $domain;
                altdns -i "$temploc/$domain/"subdomains.filtered -o "$temploc/$domain/"permutation.altdns -w "$ALTDNS_WORDS"

                debug "Starting ${PURPLE}massdns${NC} resolver." $domain;
                massdns -r "$MASSDNS_RESOLVERS" -t AAAA "$temploc/$domain/"permutation.altdns > "$temploc/$domain/"resolved.massdns
                cat "$temploc/$domain/"subdomains.filtered "$temploc/$domain/"resolved.massdns > "$temploc/$domain/"subdomains.all
        fi


        info "Starting httpx probing." $domain
        HTTPX_CMD="httpx -silent -title -status-code $HTTPX_FILTERED_PORTS -ports $HTTPX_PORTS -l $temploc/$domain/subdomains.filtered"

        if [ "$httpx_timeout" = "-1" ]; then
                $HTTPX_CMD | cut -d " " -f 1 > "$temploc/$domain/"probed.httpx
                info "Done. Found ${PURPLE}$(wc -l "$temploc/$domain/"probed.httpx | cut -d " " -f 1)${NC} live domains." $domain
        else
                timeout $httpx_timeout bash -c "$HTTPX_CMD | cut -d ' ' -f 1 > $temploc/$domain/probed.httpx" && \
                info "Done. Found ${PURPLE}$(wc -l "$temploc/$domain/"probed.httpx | cut -d " " -f 1)${NC} live domains." $domain || \
                (error "Httpx timed out." $domain)
        fi

        info "Filtering httpx output to remove duplicates"

        cp "$temploc/$domain/"probed.httpx "$temploc/$domain/"probed.httpx.orig
        grep "https://" "$temploc/$domain/probed.httpx" | sed 's/https:\/\///g' > "$temploc/$domain/"probed.httpx.https
        grep "http://" "$temploc/$domain/probed.httpx" | sed 's/http:\/\///g' > "$temploc/$domain/"probed.httpx.http
        rm -rf "$temploc/$domain/"probed.httpx

        while read -r j; do
            port="$(echo "$j" | cut -d':' -f2)"
            host="$(echo "$j" | cut -d':' -f1)"
            matching_port="${portmap[$port]}"
            echo "https://$j"  >> "$temploc/$domain/"probed.httpx
            if [ -n "$matching_port" ]; then
                httpline="$(grep -En "^$host:$matching_port$" "$temploc/$domain/"probed.httpx.http | cut -d':' -f1)"
                [ -n "$httpline" ] && sed -i "${httpline}d" "$temploc/$domain/"probed.httpx.http
            fi
        done < "$temploc/$domain/"probed.httpx.https

        sed 's/^/http:\/\//g' "$temploc/$domain/"probed.httpx.http >> "$temploc/$domain/"probed.httpx
        rm -rf "$temploc/$domain/"probed.httpx.http "$temploc/$domain/"probed.httpx.https

        sort "$temploc/$domain"/probed.httpx > "$temploc/$domain"/probed.httpx.tmp
        uniq "$temploc/$domain"/probed.httpx.tmp > "$temploc/$domain"/probed.httpx
        rm -rf "$temploc/$domain"/probed.httpx.tmp

        if [ "$dom_burpscan" = 1 ] || [ "$burpscan" ]; then
                info "Sending found endpoints to burpsuite for automatic scan." $domain
                add_to_burp_pool "$temploc/$domain/"probed.httpx &
                burp_pid="$!"
        fi

        if [ "$dom_dalfox" = 1 ] || [ "$dalfox" ]; then
                info "Sending found endpoints to dalfox for automatic scan." $domain
                dalfox_send "$temploc/$domain/"probed.httpx &
                dalfox_pid="$!"
        fi

        if [ "$dom_takeover" = 1 ] || [ "$takeover" ]; then
                info "Starting subdomain takeover scan." $domain
                subjack -t $thread_num -c $SUBJACK_FINGERPRINTS -a -v -w "$temploc/$domain/"probed.httpx > "$temploc/$domain/"takeover.subjack
        fi

        # Screenshotting
        if [ "$dom_screenshot" = 1 ] || [ "$screenshot" ]; then
                mkdir "$temploc/$domain/"screenshots;
                info "Starting screenshotting." $domain;
                cat "$temploc/$domain/"probed.httpx | aquatone -out "$temploc/$domain/"screenshots -threads $thread_num > "$temploc/$domain/"screenshots/stdout.aquatone 2> "$temploc/$domain/"screenshots/stderr.aquatone
        fi

        # Discovery
        if [ "$dom_gau" = 1 ] || [ "$gau" ]; then
                debug "Starting discovery using gau." $domain;
                cat "$temploc/$domain/"probed.httpx | timeout 3600 gau -b 'ttf,woff,svg,png,jpg' -o "$temploc/$domain/"discovery.gau
                massurl -o "$temploc/$domain/"discovery.massurl "$temploc/$domain/"discovery.gau 2> /dev/null
        fi

        # Javascript
        if [ "$dom_javascript" = 1 ] || [ "$javascript" ]; then
                debug "Starting javascript analysis." $domain;
                grep '\.html' "$temploc/$domain/"discovery.gau | sort > "$temploc/$domain/"javascript/gau.htmlgrep 2> /dev/null
                getJS --complete --input "$temploc/$domain/"javascript/grephtml >  "$temploc/$domain/"javascript/getjs.stdout 2> /dev/null
                foo=$(pwd)
                mkdir -p "$temploc/$domain/"javascript/jsfiles
                cd "$temploc/$domain/"javascript/jsfiles
                wget -quiet -i "$temploc/$domain/"javascript/getjs.stdout 2> /dev/null > /dev/null
                cd "$foo"
                linkfinder -i "$temploc/$domain/"'javascript/jsfiles/*' -o cli > "$temploc/$domain/"javascript/linkfinder.stdout
                grep '\.js' "$temploc/$domain/"javascript/linkfinder.stdout | sort > "$temploc/$domain/"javascript/linkfinder.jsgrep
                comm "$temploc/$domain/"javascript/linkfinder.jsgrep "$temploc/$domain/"javascript/gau.htmlgrep > "$temploc/$domain/"javascript/jsdiff.comm
                cd "$temploc/$domain/"javascript/jsfiles
                wget -quiet -i "$temploc/$domain/"javascript/jsdiff.comm 2> /dev/null > /dev/null
                cd "$foo"
                # TODO add static JS analysis
        fi

        # Fuzz
        if [ "$dom_fuzz" = 1 ] || [ "$fuzz" ]; then
                grep -Ev ".*api.*\\.[^.]+\\.[^.]+$" probed.httpx > probed.httpx.website
                grep -E ".*api.*\\.[^.]+\\.[^.]+$" probed.httpx > probed.httpx.api
                debug "Starting fuzzing website endpoints using ffuf." $domain;
                ffuf $FFUF_OPTS -u FIRST/SECOND -o "$temploc/$domain/fuzz.website" -w "$temploc/$domain/probed.httpx.website:FIRST" -w "$FUZZ_WORDLIST:SECOND" > /dev/null > /dev/null
                debug "Starting fuzzing api endpoints using ffuf." $domain;
                ffuf $FFUF_OPTS -u FIRST/SECOND -o "$temploc/$domain/fuzz.api" -w "$temploc/$domain/probed.httpx.api:FIRST" -w "$FUZZ_WORDLIST:SECOND" > /dev/null 2> /dev/null
        fi

        info "Done." $domain
        cd "$startloc"
        rm -rf "$startloc/$domain"
        mv "$temploc/$domain" "$startloc"
        wait "$burp_pid"
        wait "$dalfox_pid"
}

tester(){
        sleep 0.1
}

if [ -z "$devtest" ]; then
        jobnum="$(wc -l "$domfile" | cut -d ' ' -f 1)"
else
        jobnum="$devtest"
fi

scan_complete(){
        # TODO add color
        tmsg="SCAN COMPLETED"
        echo "SCAN COMPLETED"
        cat */subdomains.all > subdomains.all
        subs="$(wc -l subdomains.all | cut -d' ' -f1)"
        echo "  $subs subdomains found"
        tmsg="$tmsg%0A  $subs subdomains found"
        if [ "$httpx_blacklist" ]; then
                cat */subdomains.filtered > subdomains.filtered
                filtered="$(wc -l subdomains.filtered | cut -d' ' -f1)"
                echo "  $filtered subdomains left after filtering"
                tmsg="$tmsg%0A  $probed subdomains left after filtering"
        fi
        cat */probed.httpx > probed.httpx
        probed="$(wc -l probed.httpx | cut -d' ' -f1)"
        echo "  $probed live endpoints found"
        tmsg="$tmsg%0A  $probed live endpoints found"
        if [ "$dom_takeover" = 1 ] || [ "$takeover" ]; then
                cat */takeover.subjack > takeover.subjack
                takeover="$(grep -v "Not Vulnerable" takeover.subjack | wc -l | cut -d' ' -f1)"
                echo "  $takeover subdomain takeovers found"
                tmsg="$tmsg%0A  $takeover subdomain takeovers found"
        fi
        if [ "$dom_gau" = 1 ] || [ "$gau" ]; then
                cat */discovery.gau > discovery.gau
                gau="$(wc -l discovery.gau | cut -d' ' -f1)"
                echo "  $gau urls found with gau"
                tmsg="$tmsg%0A  $gau urls found with gau"
        fi
        if [ "$dom_fuzz" = 1 ] || [ "$fuzz" ]; then
                cat */fuzz.website > fuzz.website
                cat */fuzz.api > fuzz.api
                website="$(wc -l fuzz.website | cut -d' ' -f1)"
                api="$(wc -l fuzz.api | cut -d' ' -f1)"
                echo "  $website website paths found with fuzzing"
                tmsg="$tmsg%0A  $website website paths found with fuzzing"
                echo "  $api api paths found with fuzzing"
                tmsg="$tmsg%0A  $api api paths found with fuzzing"
        fi
        [ "$notify" ] && curl -s -d "text=${tmsg}&chat_id=${TELEGRAM_CHATID}&parse_mode=MarkdownV2" "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" > /dev/null 2> /dev/null
}

########################
# Job Pool Utils
########################
job_pool_end_of_jobs="JOBPOOL_END_OF_JOBS"
job_pool_job_queue=/tmp/job_pool_job_queue_$$
job_pool_progress=/tmp/job_pool_progress_$$
telegram_message=/tmp/telegram_message_$$
telegram_message_id=/tmp/telegram_message_id_$$
job_pool_pool_size=-1
job_pool_nerrors=0

_update_status(){
        exec 100<> $telegram_message
        flock -w 2 100
        id=$1
        movement=$((process_num - id + 1))
        tmovement=$((id + 3))
        domain=$2
        completed_jobs=$(cat $job_pool_progress)
        tmsg=$(cat $telegram_message)
        tmsg_bar="$(gen_progress_bar $(($completed_jobs*100/$jobnum)) 20 md)"
        tmsg=$(echo "$tmsg" | sed "s/%0A/\n/g" | sed "${tmovement}s/.*/*$((id+1))*: $domain/")
        tmsg="$(echo "$tmsg" | head -n -1 | sed ':a;N;$!ba;s/\n/%0A/g')%0A$tmsg_bar"
        echo -n $tmsg > $telegram_message
        _telegram_update "$tmsg"
        bar="$(gen_progress_bar $(($completed_jobs*100/$jobnum)) $BAR_LENGTH)"
        echo -en "\e[${movement}A\r\e[K$((id + 1)): $domain\e[${movement}B\e[1A\r\e[K$bar\e[1B\r"
        flock --unlock 100
}

_telegram_init(){
        if [ "$notify" ]; then
                tid="$(curl -s -d "text=${1}&chat_id=${TELEGRAM_CHATID}&parse_mode=MarkdownV2" "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" | jq -r ".result|.message_id")"
                echo -n "$tid" > $telegram_message_id
        fi
}

_telegram_update(){
        if [ "$notify" ]; then
                tid=$(cat "$telegram_message_id")
                curl -s -d "text=${1}&chat_id=${TELEGRAM_CHATID}&message_id=$tid&parse_mode=MarkdownV2" "https://api.telegram.org/bot${TELEGRAM_TOKEN}/editMessageText" > /dev/null
        fi
}

init_status(){
        tmsg="BRUNHILDA%0A\\=\\=\\=%0A"
        for i in $(seq 1 $process_num); do
                echo "$i: INITIALIZING"
                tmsg="$tmsg*$i*: INITIALIZING%0A"
        done
        tmsg="$tmsg*$(gen_progress_bar 0 20 'md')*"
        echo "$tmsg" > "$telegram_message"
        _telegram_init "$tmsg"
        gen_progress_bar 0 $BAR_LENGTH
        echo -n 0 > $job_pool_progress
}

gen_progress_bar(){
        progress_percent=$1
        if [ "$3" = "md" ]; then
                bar="$(python -c "print('\\='*int($progress_percent*$2/100) + '\\>' + ' '*($2-int($progress_percent*$2/100)))")"
                echo "\\($progress_percent%\\) \\[$bar\\]"
        else
                bar="$(python -c "print('='*int($progress_percent*$2/100) + '>' + ' '*($BAR_LENGTH-int($progress_percent*$2/100)))")"
                echo "($progress_percent%) [$bar]"
        fi
}

function _job_complete(){
        exec 103<> $telegram_message
        flock -w 2 103
        completed_jobs=$(cat $job_pool_progress)
        ((completed_jobs++))
        echo -n $completed_jobs > $job_pool_progress
        _update_status "$1" "$2"
        flock --unlock 103
}

function _job_pool_cleanup()
{
        rm -f ${job_pool_job_queue}
        rm -f ${job_pool_progress}
        rm -rf ${telegram_message}
        rm -rf ${telegram_message_id}
}

function _job_pool_exit_handler()
{
        _job_pool_stop_workers
        _job_pool_cleanup
}

function _job_pool_worker()
{
        local id=$1
        local job_queue=$2
        local cmd=
        local args=

        exec 7<> ${job_queue}
        while [[ "${cmd}" != "${job_pool_end_of_jobs}" && -e "${job_queue}" ]]; do
                flock --exclusive 7
                IFS=$'\v'
                read cmd args <${job_queue}
                set -- ${args}
                unset IFS
                flock --unlock 7
                if [[ "${cmd}" == "${job_pool_end_of_jobs}" ]]; then
                        echo "${cmd}" >&7
                else
                        if [ -z "$devtest" ]; then
                                _update_status $id $(echo $@ | cut -d',' -f1)
                                { ${cmd} "$@" ; }
                                _job_complete $id $@
                        else
                                #echo CMD\($i\): ${cmd} "$@"
                                _update_status $id "$cmd $@"
                                { ${cmd} "$@" ; }
                                _job_complete $id "$cmd $@"
                        fi
                fi

        done
        exec 7>&-
}

function _job_pool_stop_workers()
{
        echo ${job_pool_end_of_jobs} >> ${job_pool_job_queue}
        wait
}

function _job_pool_start_workers()
{
        local job_queue=$1
        for ((i=0; i<${job_pool_pool_size}; i++)); do
        _job_pool_worker ${i} ${job_queue} &
        done
}

function job_pool_init()
{
        local pool_size=$1
        job_pool_pool_size=${pool_size:=1}
        rm -rf ${job_pool_job_queue}
        rm -rf ${job_pool_progress}
        rm -rf ${telegram_message}
        rm -rf ${telegram_message_id}
        touch ${job_pool_progress}
        touch ${telegram_message}
        touch ${telegram_message_id}
        mkfifo ${job_pool_job_queue}
        echo 0 >${job_pool_progress} &
        _job_pool_start_workers ${job_pool_job_queue}
}

function job_pool_shutdown()
{
        _job_pool_stop_workers
        _job_pool_cleanup
}

function job_pool_run()
{
        if [[ "${job_pool_pool_size}" == "-1" ]]; then
        job_pool_init
        fi
        printf "%s\v" "$@" >> ${job_pool_job_queue}
        echo >> ${job_pool_job_queue}
}

function job_pool_wait()
{
        _job_pool_stop_workers
        _job_pool_start_workers ${job_pool_job_queue}
}
#########################################
# End of Job Pool
#########################################

job_pool_init $process_num 0
init_status $process_num

# Subdomain Enumeration
if [ -z "$devtest" ]; then
        while read -r i; do
                job_pool_run release_the_hounds "$i"
        done < "${domfile:-/dev/stdin}"
        rm -rf $temploc
else
        for i in $(seq 1 $devtest); do
                job_pool_run tester "$i" $i
        done
fi

job_pool_wait
job_pool_shutdown

if [ -z "$devtest" ]; then
        scan_complete
else
        info_out "Completed"
fi
