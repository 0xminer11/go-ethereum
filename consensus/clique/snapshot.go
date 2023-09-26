// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package clique

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

const (
	// This is the amount of time spent waiting in between redialing a certain node. The
	// limit is a bit higher than inboundThrottleTime to prevent failing dials in small
	// private networks

	// Config for the  Round Robin Time
	dialStatsLogInterval = 100 * time.Second // For Each time

	// Endpoint resolution is throttled with bounded backoff.
	initialResolveDelay = 60 * time.Second
	maxResolveDelay     = time.Hour
)

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes)
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account
}

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal
}

/* This struct will store Informaion of every node of Network.
	@Owner: address of each node
	@OStakes : The Number of stakes each node staked
	@Timestamp : The timestamp of each node entry in the Network
	@MiningPower : Mining Power of each node
*/
type TallyStake struct {
	Owner     common.Address `json:"owner"`
	OStakes   uint64         `json:"o_stakes"`
	Timestamp time.Time      `json:"timestamp"`
	//CoinAge   uint64         `json:"coin_age"`
	MiningPower uint64 `json:"mining_power"`
}

/* This struct will store the Information of selected nodes.
	@Owner: address of selected node
	@OStakes : The Number of stakes selected node staked
*/
type TallyDelegatedStake struct {
	Owner   common.Address `json:"owner"`
	OStakes uint64         `json:"o_stakes"`
}

/* This struct will store Informaion  of strong nodes in Network.
	@Owner: address of strong node
	@OStakes : The Number of stakes strong node staked
	@MiningPower : Mining Power of strong node
	@attack : attack or non attack strategy
*/
type StrongPool struct {
	Owner       common.Address `json:"owner"`
	OStakes     uint64         `json:"o_stakes"`
	MiningPower uint64         `json:"mining_power"`
	attack      bool           `json:"attack"`
}

/* This struct will store Informaion  of week nodes in Network.
	@Owner: address of week node
	@OStakes : The Number of stakes week node staked
	@MiningPower : Mining Power of week node
	@attack : attack or non attack strategy
*/
type WeekPool struct {
	Owner       common.Address `json:"owner"`
	OStakes     uint64         `json:"o_stakes"`
	MiningPower uint64         `json:"mining_power"`
	attack      bool           `json:"attack"`
}

/* This struct will store Informaion nodes who selected for miner.
	@Owner: address of miner node
	@OStakes : The Number of stakes miner node staked
	@MiningPower : Mining Power of miner node
*/
type Minerpool struct {
	Owner       common.Address `json:"owner"`
	OStakes     uint64         `json:"o_stakes"`
	MiningPower uint64         `json:"mining_power"`
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache        // Cache of recent block signatures to speed up ecrecover

	Number              uint64                      `json:"number"`                // Block number where the snapshot was created
	Hash                common.Hash                 `json:"hash"`                  // Block hash where the snapshot was created
	Signers             map[common.Address]struct{} `json:"signers"`               // Set of authorized signers at this moment
	Recents             map[uint64]common.Address   `json:"recents"`               // Set of recent signers for spam protections
	Votes               []*Vote                     `json:"votes"`                 // List of votes cast in chronological order
	Tally               map[common.Address]Tally    `json:"tally"`                 // Current vote tally to avoid recalculating
	TallyStakes         []*TallyStake               `json:"tallystakes"`           // to hold all stakes mapped to their addresses // Abhi
	StakeSigner         common.Address              `json:"stakesigner"`           // Abhi
	TallyDelegatedStake []*TallyDelegatedStake      `json:"tally_delegated_stake"` //Naveen
	StrongPool          []*StrongPool               `json:"strong_pool"`           //Naveen
	WeekPool            []*WeekPool                 `json:"week_pool"`             //Naveen
	DelegatedSigners    map[common.Address]struct{} `json:"delegated_signers"`     //Naveen
	malicious           bool						//Find malicious node
	stage1              bool						//stage 1 game
	stage2              bool						//stage 2 game
	stage3              bool						//stage 3 game
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []common.Address

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.

func newSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	log.Info("printing signers of 0 address, ")
	log.Info(signers[0].String())

	var snap = &Snapshot{
		config:           config,
		sigcache:         sigcache,
		Number:           number,
		Hash:             hash,
		Signers:          make(map[common.Address]struct{}),
		Recents:          make(map[uint64]common.Address),
		Tally:            make(map[common.Address]Tally),
		StakeSigner:      signers[0],
		DelegatedSigners: make(map[common.Address]struct{}),
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("clique-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("clique-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:      s.config,
		sigcache:    s.sigcache,
		Number:      s.Number,
		Hash:        s.Hash,
		Signers:     make(map[common.Address]struct{}),
		Recents:     make(map[uint64]common.Address),
		Votes:       make([]*Vote, len(s.Votes)),
		Tally:       make(map[common.Address]Tally),
		TallyStakes: make([]*TallyStake, len(s.TallyStakes)), // Abhi
		StakeSigner: s.StakeSigner,                           // Abhi
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	copy(cpy.Votes, s.Votes)
	copy(cpy.TallyStakes, s.TallyStakes)

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Signers[address]
	return (signer && !authorize) || (!signer && authorize)
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		log.Info("apply 202 error")
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
			log.Info("apply 209 error")
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
			//snap.TallyStakes = nil
		}
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok {
			log.Info("apply 240 error")
			//return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				//return nil, errRecentlySigned
				log.Info("recently signed")
			}
		}

		snap.Recents[number] = signer

		// Header authorized, discard any previous votes from the signer
		for i, vote := range snap.Votes {
			if vote.Signer == signer && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // only one vote allowed
			}
		}
		// Tally up the new vote from the signer
		//var authorize bool
		var in_stakes uint64 // Abhi

		/*	switch {
			case bytes.Equal(header.Nonce[:], nonceAuthVote):
				authorize = true
			case bytes.Equal(header.Nonce[:], nonceDropVote):
				authorize = false
			default:
				return nil, errInvalidVote
			}*/
		in_stakes = header.Nonce.Uint64() // Abhi
		/*if snap.cast(header.Coinbase, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Signer:    signer,
				Block:     number,
				Address:   header.Coinbase,
				Authorize: authorize,
			})
		}*/
		// Abhi -Add stakes to snapshot

		log.Info("Checking----->")
		//log.Info(header.Coinbase.String())
		fmt.Println("coinbase", header.Coinbase)
		//log.Info(string(in_stakes))
		fmt.Println(in_stakes)
		var flag bool
		var posistion int
		flag = false
		for i := 0; i < len(snap.TallyStakes); i++ {
			if snap.TallyStakes[i].Owner == header.Coinbase {
				flag = true
				posistion = i
			}
		}
		if flag == false {
			var timestamp = time.Now()
			snap.TallyStakes = append(snap.TallyStakes, &TallyStake{
				Owner:     header.Coinbase,
				OStakes:   in_stakes,
				Timestamp: timestamp,
			})
		} else {
			snap.TallyStakes[posistion].OStakes = in_stakes
		}

		fmt.Println("leangth", len(snap.TallyStakes))

		// If the vote passed, update the list of signers

		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Signers)/2 {
			if tally.Authorize {
				snap.Signers[header.Coinbase] = struct{}{}
			} else {
				delete(snap.Signers, header.Coinbase)

				// Signer list shrunk, delete any leftover recent caches
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signer cast
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.Coinbase {
						// Uncast the vote from the cached tally
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase)
		}

		// Finding Coin Age
		//now := time.Now()
		//for i := 0; i < len(snap.TallyStakes); i++ {
		//	age := now.Sub(snap.TallyStakes[i].Timestamp)
		//	snap.TallyStakes[i].CoinAge = snap.TallyStakes[i].OStakes * uint64(age)
		//
		//}
		//// Sorting a Nodes Based on timestamp
		//sort.SliceStable(snap.TallyStakes, func(i, j int) bool {
		//	return snap.TallyStakes[i].CoinAge > snap.TallyStakes[j].CoinAge
		//})
		//log.Info("Nodes in the Network")
		//for i := 0; i < len(snap.TallyStakes); i++ {
		//	fmt.Println(snap.TallyStakes[i].OStakes)
		//	fmt.Println(snap.TallyStakes[i].Owner)
		//	fmt.Println(snap.TallyStakes[i].Timestamp)
		//	fmt.Println(snap.TallyStakes[i].CoinAge)
		//}
		//snap.TallyDelegatedStake = nil
		//var f1 bool
		//f1 = false
		//for i := 0; i < len(snap.TallyStakes); i++ {
		//	for j := 0; j < len(snap.TallyDelegatedStake); j++ {
		//		if snap.TallyStakes[i].Owner == snap.TallyDelegatedStake[j].Owner {
		//			f1 = true
		//			snap.TallyDelegatedStake[j].OStakes = snap.TallyStakes[i].OStakes
		//		}
		//	}
		//	if f1 == false {
		//		if len(snap.TallyDelegatedStake) <= 5 {
		//			snap.TallyDelegatedStake = append(snap.TallyDelegatedStake, &TallyDelegatedStake{
		//				Owner:   snap.TallyStakes[i].Owner,
		//				OStakes: snap.TallyStakes[i].OStakes,
		//			})
		//		}
		//	}
		//}

		//Stage 1 Game
		avg := uint64(0)
		add := uint64(0)
		for i := 0; i < len(snap.TallyStakes); i++ {

			add = add + snap.TallyStakes[i].OStakes
			snap.TallyStakes[i].MiningPower = snap.TallyStakes[i].OStakes / 32

		}
		avg = add / uint64(len(snap.TallyStakes))
		fmt.Println("avg:", add, avg)
		var f1 bool
		for i := 0; i < len(snap.TallyStakes); i++ {
			if snap.TallyStakes[i].OStakes > avg && snap.TallyStakes[i].OStakes >= 32 {
				for j := 0; j < len(snap.StrongPool); j++ {
					if snap.TallyStakes[i].Owner == snap.StrongPool[j].Owner {
						f1 = true
						snap.StrongPool[j].OStakes = snap.TallyStakes[i].OStakes
						snap.StrongPool[j].MiningPower = snap.TallyStakes[i].MiningPower
						fmt.Println("Updated in Strong Pool")
					}
				}
				if f1 == false {
					snap.StrongPool = append(snap.StrongPool, &StrongPool{
						Owner:       snap.TallyStakes[i].Owner,
						OStakes:     snap.TallyStakes[i].OStakes,
						MiningPower: snap.TallyStakes[i].MiningPower,
					})
					fmt.Println("Chosen Strong Pool")
				}
			} else {
				for j := 0; j < len(snap.WeekPool); j++ {
					if snap.TallyStakes[i].Owner == snap.WeekPool[j].Owner {
						f1 = true
						snap.WeekPool[j].OStakes = snap.TallyStakes[i].OStakes
						snap.WeekPool[j].MiningPower = snap.TallyStakes[i].MiningPower
						fmt.Println("Updated in Week Pool")
					}
				}
				if f1 == false {
					snap.WeekPool = append(snap.WeekPool, &WeekPool{
						Owner:       snap.TallyStakes[i].Owner,
						OStakes:     snap.TallyStakes[i].OStakes,
						MiningPower: snap.TallyStakes[i].MiningPower,
					})
					fmt.Println("Chosen Week Pool")
				}

			}

		}

		// Stage two 
		snap.stage1 = false
		fmt.Println("Nodes in Network:- ")
		for i := 0; i < len(snap.TallyStakes); i++ {
			fmt.Println(snap.TallyStakes[i].OStakes)
			fmt.Println(snap.TallyStakes[i].Owner)
		}

		//addsp := uint64(0)
		//avgsp := uint64(0)
		//for i:=0;i<len(snap.StrongPool);i++{
		//	addsp=addsp +snap.StrongPool[i].MiningPower
		//}
		//avgsp =addsp/uint64(len(snap.StrongPool))
		//
		//addwp := uint64(0)
		//avgwp := uint64(0)
		//for i:=0;i<len(snap.WeekPool);i++{
		//	addwp=addwp +snap.WeekPool[i].MiningPower
		//}
		//avgwp =addwp/uint64(len(snap.WeekPool))
		addm := uint64(0)
		avgm := uint64(0)
		for i := 0; i < len(snap.TallyStakes); i++ {
			addm = addm + snap.TallyStakes[i].OStakes

		}
		avgm = addm / uint64(len(snap.TallyStakes))
		fmt.Println("Average Stake ", avgm)

		for i := 0; i < len(snap.StrongPool); i++ {
			if snap.WeekPool[i].MiningPower < avgm/4 && snap.WeekPool[i].MiningPower > avg {
				n := rand.Intn(len(snap.StrongPool))
				snap.StrongPool[n].MiningPower = snap.StrongPool[n].MiningPower - 1
				snap.StrongPool[i].MiningPower = snap.StrongPool[i].MiningPower + 1
				snap.StrongPool[i].OStakes = snap.StrongPool[i].OStakes - (snap.StrongPool[i].OStakes / 25)
				snap.StrongPool[i].attack = true
			}
		}
		for i := 0; i < len(snap.WeekPool); i++ {
			if snap.WeekPool[i].MiningPower < avgm/4 && snap.WeekPool[i].MiningPower > avg {
				n := rand.Intn(len(snap.StrongPool))
				snap.StrongPool[n].MiningPower = snap.StrongPool[n].MiningPower - 1
				snap.WeekPool[i].MiningPower = snap.WeekPool[i].MiningPower + 1
				snap.WeekPool[i].OStakes = snap.WeekPool[i].OStakes - (snap.WeekPool[i].OStakes / 25)
				snap.WeekPool[i].attack = true
			}
		}
		snap.stage2 = false

		fmt.Println("StrongPool Nodes")

		for i := 0; i < len(snap.StrongPool); i++ {
			fmt.Println(snap.StrongPool[i].OStakes)
			fmt.Println(snap.StrongPool[i].Owner)
			fmt.Println(snap.StrongPool[i].MiningPower)
		}

		fmt.Println("WeakPool Nodes")

		for i := 0; i < len(snap.WeekPool); i++ {
			fmt.Println(snap.WeekPool[i].OStakes)
			fmt.Println(snap.WeekPool[i].Owner)
			fmt.Println(snap.WeekPool[i].MiningPower)
		}

		max1S := uint64(0)
		max1O := common.Address{0}
		max1Mp := uint64(0)
		max1 := bool(false)
		max1n := int(0)
		max2S := uint64(0)
		max2O := common.Address{0}
		max2Mp := uint64(0)
		max2 := bool(false)
		max2n := int(0)

		for i := 0; i < len(snap.StrongPool); i++ {
			if max1S < snap.StrongPool[i].OStakes {
				max1S = snap.StrongPool[i].OStakes
				max1O = snap.StrongPool[i].Owner
				max1Mp = snap.StrongPool[i].MiningPower
				max1 = true
				max1n = i
			}
		}
		for i := 0; i < len(snap.StrongPool); i++ {
			if max2S < snap.StrongPool[i].OStakes && max2S < max1S {
				max2S = snap.StrongPool[i].OStakes
				max2O = snap.StrongPool[i].Owner
				max2Mp = snap.StrongPool[i].MiningPower
				max2 = true
				max2n = i
			}
		}
		for i := 0; i < len(snap.WeekPool); i++ {
			if max1S < snap.WeekPool[i].OStakes {
				max1S = snap.WeekPool[i].OStakes
				max1O = snap.WeekPool[i].Owner
				max1Mp = snap.WeekPool[i].MiningPower
				max1 = false
				max1n = i
			}
		}
		for i := 0; i < len(snap.WeekPool); i++ {
			if max2S < snap.WeekPool[i].OStakes && max2S < max1S {
				max2S = snap.WeekPool[i].OStakes
				max2O = snap.WeekPool[i].Owner
				max2Mp = snap.WeekPool[i].MiningPower
				max2 = false
				max2n = i
			}
		}

		if max2Mp > max1Mp {
			snap.StakeSigner = max2O
		} else {
			snap.StakeSigner = max1O
		}
		snap.stage3 = false
		m11 := uint64(0)
		m12 := uint64(0)
		m13 := uint64(0)
		m14 := uint64(0)
		if max1 == true && snap.StrongPool[max1n].attack == false {
			m11 = snap.StrongPool[max1n].MiningPower
			m11 = m11 + 1
		}
		if max1 == true && snap.StrongPool[max1n].attack == true {
			m11 = snap.StrongPool[max1n].MiningPower
			m12 = m12 - 1
		}
		if max1 == false && snap.WeekPool[max1n].attack == false {
			m13 = snap.WeekPool[max1n].MiningPower
			m13 = m13 + 1
		}
		if max1 == false && snap.WeekPool[max1n].attack == true {
			m14 = snap.WeekPool[max1n].MiningPower
			m14 = m14 - 1
		}

		fmt.Println("Top Player Matrix")

		fmt.Println("-----------------------")
		fmt.Println("|   ", m11, " | ", m12, "      |")
		fmt.Println("-----------------------")
		fmt.Println("|   ", m13, " | ", m14, "      |")
		fmt.Println("-----------------------")

		m21 := uint64(0)
		m22 := uint64(0)
		m23 := uint64(0)
		m24 := uint64(0)

		if max2 == true && snap.StrongPool[max2n].attack == false {
			m21 = snap.StrongPool[max1n].MiningPower
			m21 = m21 + 1
		}
		if max2 == true && snap.StrongPool[max2n].attack == true {
			m22 = snap.StrongPool[max1n].MiningPower
			m22 = m22 - 1
		}
		if max2 == false && snap.WeekPool[max2n].attack == false {
			m23 = snap.WeekPool[max1n].MiningPower
			m23 = m23 + 1
		}
		if max2 == false && snap.WeekPool[max2n].attack == true {
			m24 = snap.WeekPool[max1n].MiningPower
			m24 = m24 - 1
		}
		fmt.Println("Second Top Player Matrix")

		fmt.Println("-----------------------")
		fmt.Println("|   ", m21, " | ", m22, "      |")
		fmt.Println("-----------------------")
		fmt.Println("|   ", m23, " | ", m24, "      |")
		fmt.Println("-----------------------")

		//fmt.Println("Second Top Player Matrix")
		//
		//fmt.Println("-----------------------")
		//fmt.Println("|   ", m11," | ",m12,"      |")
		//fmt.Println("-----------------------")
		//fmt.Println("|   ", m23," | ",m24,"      |")
		//fmt.Println("-----------------------")

		//log.Info("Delegated Nodes")
		//for i := 0; i < len(snap.TallyDelegatedStake); i++ {
		//	fmt.Println(snap.TallyDelegatedStake[i].OStakes)
		//	fmt.Println(snap.TallyDelegatedStake[i].Owner)
		//}

		// Random miner
		//n := rand.Intn(len(snap.TallyDelegatedStake)-0) + 0
		//snap.StakeSigner = snap.TallyDelegatedStake[n].Owner

		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(signersAscending(sigs))
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset)
}
