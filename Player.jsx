import React, { useState, useEffect, useRef } from 'react';

const Player = ({
    currentSong,
    isPlaying,
    togglePlay,
    currentTime,
    duration,
    seek,
    volume,
    changeVolume
}) => {

    const handleSeek = (e) => {
        const seekTime = parseFloat(e.target.value);
        seek(seekTime);
    };

    const handleVolumeChange = (e) => {
        const newVol = parseFloat(e.target.value);
        changeVolume(newVol);
    };

    function formatTime(seconds) {
        if (!seconds || isNaN(seconds)) return "0:00";
        const min = Math.floor(seconds / 60);
        const sec = Math.floor(seconds % 60);
        return `${min}:${sec < 10 ? '0' : ''}${sec}`;
    }

    // --- Render UI ---
    return (
        <div className="player-bar">
            {/* Song Info */}
            <div className="song-info">
                <h4>{currentSong?.title || "No Song"}</h4>
                <p>{currentSong?.artist || "Select a track"}</p>
            </div>

            {/* Controls */}
            <div className="controls-section">
                <button onClick={togglePlay} className="play-btn">
                    {isPlaying ? "❚❚ Pause" : "▶ Play"}
                </button>

                <div className="progress-wrapper">
                    <span>{formatTime(currentTime)}</span>
                    <input
                        type="range"
                        min="0"
                        max={duration || 0}
                        value={currentTime}
                        onChange={handleSeek}
                        className="seek-slider"
                    />
                    <span>{formatTime(duration)}</span>
                </div>
            </div>

            {/* Volume */}
            <div className="volume-section">
                <label>Vol: </label>
                <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={volume}
                    onChange={handleVolumeChange}
                />
            </div>
        </div>
    );
};

export default Player;
